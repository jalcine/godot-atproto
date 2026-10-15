extends Node

const HANDLE := "jacky.blacksky.app"

var client: AtprotoClient


func _ready() -> void:
	client = AtprotoClient.new()
	add_child(client)
	client.authorize_url_ready.connect(_on_authorize_url_ready)
	client.sign_in_completed.connect(_on_sign_in_completed)
	client.sign_in_failed.connect(_on_sign_in_failed)
	print("godot_atproto version: ", client.version())
	print("Signing in as ", HANDLE)
	client.sign_in(HANDLE)


func _on_authorize_url_ready(url: String) -> void:
	print("Opening authorize URL in the browser")
	OS.shell_open(url)


func _on_sign_in_completed(did: String) -> void:
	print("Signed in as ", did)


func _on_sign_in_failed(message: String) -> void:
	print("Sign-in failed: ", message)
	get_tree().quit(1)
