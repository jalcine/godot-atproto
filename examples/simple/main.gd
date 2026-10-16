extends Node

const SCOPE := "transition:generic atproto"

var client: AtprotoClient
@onready var did_label: Label = $DidLabel


func _ready() -> void:
	client = AtprotoClient.new()
	add_child(client)
	print("godot-atproto version: ", client.version())

	client.authorize_url_ready.connect(_on_authorize_url_ready)
	client.sign_in_completed.connect(_on_sign_in_completed)
	client.sign_in_cancelled.connect(_on_sign_in_cancelled)
	client.sign_in_failed.connect(_on_sign_in_failed)

	$SignIn/SignInButton.pressed.connect(_on_sign_in_pressed)


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
	print("PDS: ", client.get_pds_url())

	var uri := _create_post("this is a post from godot-rust!")
	print("created post: ", uri)
	if uri.is_empty():
		push_error("createRecord failed")
	else:
		var rkey := uri.get_file()
		print("read back: ", client.get_record("app.bsky.feed.post", rkey))

	client.sign_out()
	print("after sign-out, DID is ", client.get_did(), " (empty == cleared)")

func _on_sign_in_cancelled() -> void:
	print("sign-in cancelled")


func _on_sign_in_failed(message: String) -> void:
	push_error("sign-in failed: ", message)


func _create_post(text: String) -> String:
	var body := {
		"repo": client.get_did(),
		"collection": "app.bsky.feed.post",
		"record": {
			"$type": "app.bsky.feed.post",
			"text": text,
			"createdAt": Time.get_datetime_string_from_system(true, false) + "Z",
		},
	}
	var response := client.xrpc_procedure("com.atproto.repo.createRecord", JSON.stringify(body))
	if response.is_empty():
		return ""
	var parsed = JSON.parse_string(response)
	if parsed is Dictionary and parsed.has("uri"):
		return parsed["uri"]
	return ""
