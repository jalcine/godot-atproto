extends Node

const HANDLE := "jaybesaying.afrolatinsky.app"
const SCOPE := "transition:generic atproto"

var client: AtprotoClient


func _ready() -> void:
	client = AtprotoClient.new()
	add_child(client)
	print("godot-atproto version: ", client.version())

	client.authorize_url_ready.connect(_on_authorize_url_ready)
	client.sign_in_completed.connect(_on_sign_in_completed)
	client.sign_in_cancelled.connect(_on_sign_in_cancelled)
	client.sign_in_failed.connect(_on_sign_in_failed)

	print("signing in as ", HANDLE, " with scope ", SCOPE)
	if not client.sign_in(HANDLE, SCOPE):
		push_error("sign-in already in progress")


func _on_authorize_url_ready(url: String) -> void:
	print("authorize URL: ", url)
	OS.shell_open(url)


func _on_sign_in_completed(did: String) -> void:
	print("signed in as ", did)
	print("PDS: ", client.get_pds_url())

	var uri := client.create_post("this is a post from godot-rust!")
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
