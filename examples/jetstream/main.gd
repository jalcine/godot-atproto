extends Node

const SCOPE := "transition:generic atproto"
const SAMPLE_ACCOUNTS := 64
const POSTS_PER_ACCOUNT := 50
const FOLLOW_PAGE_LIMIT := 100
const PLC_DIRECTORY := "https://plc.directory/"
const MAX_CONCURRENT_ACCOUNTS := 8
const MIN_AUTHORS := 4

var client: AtprotoClient
var follows: Array[String] = []
var sampled_dids: Array[String] = []
var posts_by_did: Dictionary = {}
var names_by_did: Dictionary = {}

# Distinct follows not yet sampled, in random order. A failed account is
# replaced by the next one here, so the game still reaches SAMPLE_ACCOUNTS.
var _spare_dids: Array[String] = []
var _post_queue: Array[String] = []
var _in_flight: int = 0
var _failed: int = 0

@onready var did_label: Label = $DidLabel
@onready var status_label: Label = $StatusLabel
@onready var play_button: Button = $PlayButton


func _ready() -> void:
	client = AtprotoClient.new()
	add_child(client)
	print("godot-atproto version: ", client.version())

	client.authorize_url_ready.connect(_on_authorize_url_ready)
	client.sign_in_completed.connect(_on_sign_in_completed)
	client.sign_in_cancelled.connect(_on_sign_in_cancelled)
	client.sign_in_failed.connect(_on_sign_in_failed)

	$SignIn/SignInButton.pressed.connect(_on_sign_in_pressed)
	play_button.pressed.connect(_on_play_pressed)


func _on_sign_in_pressed() -> void:
	var handle: String = $SignIn/HandleInput.text.strip_edges()
	if handle.is_empty():
		push_error("enter a handle first")
		return
	print("signing in as ", handle, " with scope ", SCOPE)
	if not client.sign_in(handle, SCOPE):
		push_error("sign-in already in progress")


func _on_authorize_url_ready(url: String) -> void:
	print("authorize URL: ", url)
	OS.shell_open(url)


func _on_sign_in_completed(did: String) -> void:
	print("signed in as ", did)
	did_label.text = did
	_load_game_data()


func _on_sign_in_cancelled() -> void:
	print("sign-in cancelled")


func _on_sign_in_failed(message: String) -> void:
	push_error("sign-in failed: ", message)


func _load_game_data() -> void:
	status_label.text = "Loading follows..."
	follows = _fetch_all_follows(client.get_did())
	print("follows loaded: ", follows.size())
	var pool := _shuffled_distinct(follows)
	if pool.size() < SAMPLE_ACCOUNTS:
		status_label.text = "Need at least %d follows, found %d" % [SAMPLE_ACCOUNTS, pool.size()]
		push_error(status_label.text)
		return

	for i in SAMPLE_ACCOUNTS:
		sampled_dids.append(pool[i])
	for i in range(SAMPLE_ACCOUNTS, pool.size()):
		_spare_dids.append(pool[i])
	_post_queue = sampled_dids.duplicate()
	status_label.text = "Fetching posts for %d accounts..." % SAMPLE_ACCOUNTS
	_pump_post_queue()


# Pages through app.bsky.graph.follow records in the signed-in repo via the
# authenticated XRPC path. xrpc_query blocks, so this runs once at startup.
func _fetch_all_follows(repo: String) -> Array[String]:
	var result: Array[String] = []
	var cursor := ""
	while true:
		var params := {
			"repo": repo,
			"collection": "app.bsky.graph.follow",
			"limit": str(FOLLOW_PAGE_LIMIT),
		}
		if not cursor.is_empty():
			params["cursor"] = cursor
		var response := client.xrpc_query("com.atproto.repo.listRecords", params)
		if response.is_empty():
			push_error("listRecords failed while paging follows")
			break
		var parsed = JSON.parse_string(response)
		if not (parsed is Dictionary):
			push_error("listRecords returned non-JSON")
			break
		for record in parsed.get("records", []):
			var subject = record.get("value", {}).get("subject", "")
			if subject is String and subject.begins_with("did:"):
				result.append(subject)
		cursor = parsed.get("cursor", "")
		if cursor.is_empty():
			break
	return result


# Every distinct DID in `source`, in uniformly random order.
func _shuffled_distinct(source: Array[String]) -> Array[String]:
	var seen: Dictionary = {}
	var pool: Array[String] = []
	for did in source:
		if not seen.has(did):
			seen[did] = true
			pool.append(did)
	pool.shuffle()
	return pool


func _pump_post_queue() -> void:
	while _in_flight < MAX_CONCURRENT_ACCOUNTS and not _post_queue.is_empty():
		var did: String = _post_queue.pop_front()
		_in_flight += 1
		_resolve_pds(did)
	if _in_flight == 0 and _post_queue.is_empty():
		_on_all_done()


# Resolves a DID to its PDS via plc.directory. Each stage uses its own
# HTTPRequest node, so no signal connection needs to be swapped mid-flight.
func _resolve_pds(did: String) -> void:
	var request := HTTPRequest.new()
	add_child(request)
	request.request_completed.connect(_on_did_document.bind(did, request))
	if request.request(PLC_DIRECTORY + did) != OK:
		_fail(did, "plc request could not start", request)


func _on_did_document(result: int, code: int, _headers: PackedStringArray, body: PackedByteArray, did: String, request: HTTPRequest) -> void:
	var pds := ""
	if result == HTTPRequest.RESULT_SUCCESS and code == 200:
		var doc = JSON.parse_string(body.get_string_from_utf8())
		if doc is Dictionary:
			for service in doc.get("service", []):
				if service.get("id", "") == "#atproto_pds":
					pds = service.get("serviceEndpoint", "")
					break
	request.queue_free()
	if pds.is_empty():
		_fail(did, "no PDS in DID document (result %d, HTTP %d)" % [result, code], null)
		return
	_fetch_posts(did, pds)


func _fetch_posts(did: String, pds: String) -> void:
	var request := HTTPRequest.new()
	add_child(request)
	request.request_completed.connect(_on_posts.bind(did, pds, request))
	var url := "%s/xrpc/com.atproto.repo.listRecords?repo=%s&collection=app.bsky.feed.post&limit=%d" % [
		pds.trim_suffix("/"), did.uri_encode(), POSTS_PER_ACCOUNT,
	]
	if request.request(url) != OK:
		_fail(did, "listRecords could not start", request)


func _on_posts(result: int, code: int, _headers: PackedStringArray, body: PackedByteArray, did: String, pds: String, request: HTTPRequest) -> void:
	request.queue_free()
	if result != HTTPRequest.RESULT_SUCCESS or code != 200:
		_fail(did, "posts fetch failed (result %d, HTTP %d)" % [result, code], null)
		return
	var parsed = JSON.parse_string(body.get_string_from_utf8())
	if not (parsed is Dictionary):
		_fail(did, "posts response was not JSON", null)
		return
	var texts: Array[String] = []
	for record in parsed.get("records", []):
		var text = record.get("value", {}).get("text", "")
		if text is String and not text.is_empty():
			texts.append(text)
	if texts.is_empty():
		_fail(did, "account has no posts", null)
		return
	posts_by_did[did] = texts
	_fetch_profile(did, pds)


# Loads the account's app.bsky.actor.profile/self record from its own PDS.
func _fetch_profile(did: String, pds: String) -> void:
	var request := HTTPRequest.new()
	add_child(request)
	request.request_completed.connect(_on_profile.bind(did, request))
	var url := "%s/xrpc/com.atproto.repo.getRecord?repo=%s&collection=app.bsky.actor.profile&rkey=self" % [
		pds.trim_suffix("/"), did.uri_encode(),
	]
	if request.request(url) != OK:
		_use_did_as_name(did, "profile request could not start", request)


func _on_profile(result: int, code: int, _headers: PackedStringArray, body: PackedByteArray, did: String, request: HTTPRequest) -> void:
	request.queue_free()
	if result != HTTPRequest.RESULT_SUCCESS or code != 200:
		_use_did_as_name(did, "profile fetch failed (result %d, HTTP %d)" % [result, code], null)
		return
	var parsed = JSON.parse_string(body.get_string_from_utf8())
	var display = ""
	if parsed is Dictionary:
		display = parsed.get("value", {}).get("displayName", "")
	if not (display is String) or display.strip_edges().is_empty():
		_use_did_as_name(did, "profile has no displayName", null)
		return
	names_by_did[did] = display
	_finish_one()


func _use_did_as_name(did: String, reason: String, request: HTTPRequest) -> void:
	push_warning("%s: %s; showing DID instead" % [did, reason])
	if request != null:
		request.queue_free()
	names_by_did[did] = did
	_finish_one()


# Marks one account as unusable and, if a spare remains, queues a random
# replacement. Keeps the number of usable accounts at SAMPLE_ACCOUNTS.
func _fail(did: String, reason: String, request: HTTPRequest) -> void:
	push_error("%s: %s" % [did, reason])
	if request != null:
		request.queue_free()
	_failed += 1
	posts_by_did.erase(did)
	sampled_dids.erase(did)
	if not _spare_dids.is_empty():
		var replacement: String = _spare_dids.pop_front()
		sampled_dids.append(replacement)
		_post_queue.append(replacement)
		print("replacing ", did, " with ", replacement)
	_finish_one()


func _finish_one() -> void:
	_in_flight -= 1
	status_label.text = "Loaded %d / %d accounts" % [posts_by_did.size(), sampled_dids.size()]
	_pump_post_queue()


func _on_all_done() -> void:
	print("posts loaded for ", posts_by_did.size(), " accounts; failed: ", _failed, "; spares left: ", _spare_dids.size())
	status_label.text = "Loaded posts for %d accounts (%d failed)" % [posts_by_did.size(), _failed]
	GameState.posts_by_did = posts_by_did
	GameState.names_by_did = names_by_did
	play_button.disabled = posts_by_did.size() < MIN_AUTHORS


func _on_play_pressed() -> void:
	get_tree().change_scene_to_file("res://guess.tscn")
