extends Node

const HANDLE := "jacky.blacksky.app"

var client: AtprotoClient


func _ready() -> void:
	client = AtprotoClient.new()
	add_child(client)
	print("godot-atproto version: ", client.version())

	client.authorize_url_ready.connect(_on_authorize_url_ready)
	client.sign_in_completed.connect(_on_sign_in_completed)
	client.sign_in_failed.connect(_on_sign_in_failed)

	print("signing in as ", HANDLE)
	if not client.sign_in(HANDLE):
		push_error("sign-in already in progress")


func _on_authorize_url_ready(url: String) -> void:
	print("authorize URL: ", url)
	OS.shell_open(url)


func _on_sign_in_completed(did: String) -> void:
	print("signed in as ", did)


func _on_sign_in_failed(message: String) -> void:
	push_error("sign-in failed: ", message)
