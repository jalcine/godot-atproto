extends Node
## Demonstrates the AtprotoClient GDExtension alongside the ported RpgActor
## public API: sign in and read your own actor.rpg.stats record over
## authenticated XRPC (AtprotoClient), while sprite lookup, actor search, and
## registry metrics go through rpg.actor's own public REST API (RpgActor).

const SCOPE := "transition:generic atproto repo:actor.rpg.stats repo:actor.rpg.sprite"
const _DIRECTION_ANIMATIONS := {
	"ui_down": "walk_down",
	"ui_left": "walk_left",
	"ui_right": "walk_right",
	"ui_up": "walk_up",
}

var client: AtprotoClient

@onready var did_label: Label = $DidLabel
@onready var stats_label: Label = $StatsLabel
@onready var sprite: AnimatedSprite2D = $Sprite
@onready var metrics_label: Label = $MetricsLabel
@onready var results_label: Label = $Search/ResultsLabel


func _ready() -> void:
	client = AtprotoClient.new()
	add_child(client)
	print("godot-atproto version: ", client.version())

	client.authorize_url_ready.connect(_on_authorize_url_ready)
	client.sign_in_completed.connect(_on_sign_in_completed)
	client.sign_in_cancelled.connect(_on_sign_in_cancelled)
	client.sign_in_failed.connect(_on_sign_in_failed)

	$SignIn/SignInButton.pressed.connect(_on_sign_in_pressed)
	$Search/SearchButton.pressed.connect(_on_search_pressed)

	_load_registry_metrics()


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
	_load_own_stats(did)
	_load_own_sprite(did)


func _on_sign_in_cancelled() -> void:
	print("sign-in cancelled")


func _on_sign_in_failed(message: String) -> void:
	push_error("sign-in failed: ", message)


## Reads the signed-in player's own stats record straight from their PDS,
## using the extension's authenticated XRPC path (no rpg.actor involved).
func _load_own_stats(did: String) -> void:
	var record := client.get_record("actor.rpg.stats", "self")
	if record.is_empty():
		stats_label.text = "No actor.rpg.stats record found"
		return
	stats_label.text = record


## Fetches the player's normalized sprite sheet through rpg.actor's public
## REST API (RpgActor.get_sprite), independent of the OAuth session, and
## slices it into a walk-cycle SpriteFrames: rpg.actor normalizes every
## sprite to a 144x192 sheet of 48x48 cells, 3 frames (columns) per
## direction x 4 directions (rows: down, left, right, up).
func _load_own_sprite(did: String) -> void:
	var png_bytes: PackedByteArray = await RpgActor.get_sprite(did)
	if png_bytes.is_empty():
		push_warning("no sprite available for %s" % [did])
		return
	var image := Image.new()
	if image.load_png_from_buffer(png_bytes) != OK:
		push_warning("could not decode sprite PNG for %s" % [did])
		return
	var texture := ImageTexture.create_from_image(image)

	var frames := SpriteFrames.new()
	var row_animations := ["walk_down", "walk_left", "walk_right", "walk_up"]
	for row in row_animations.size():
		var animation_name: String = row_animations[row]
		frames.add_animation(animation_name)
		frames.set_animation_speed(animation_name, 8.0)
		for column in 3:
			var frame_texture := AtlasTexture.new()
			frame_texture.atlas = texture
			frame_texture.region = Rect2(column * 48, row * 48, 48, 48)
			frames.add_frame(animation_name, frame_texture)

	sprite.sprite_frames = frames
	sprite.play("walk_down")


## Each row is a 3-frame walk-cycle loop; it plays continuously once loaded.
## Holding an arrow key just switches which direction's loop is playing.
func _process(_delta: float) -> void:
	if sprite.sprite_frames == null:
		return
	for action in _DIRECTION_ANIMATIONS:
		if Input.is_action_pressed(action):
			var animation_name: String = _DIRECTION_ANIMATIONS[action]
			if sprite.animation != animation_name:
				sprite.play(animation_name)
			return


## Registry-wide summary, available without signing in.
func _load_registry_metrics() -> void:
	var stats: Dictionary = await RpgActor.metrics()
	var health: Dictionary = await RpgActor.health()
	metrics_label.text = "rpg.actor: %s actors, %s systems - %s" % [
		stats.get("actorCount", "?"),
		stats.get("systemCount", "?"),
		health.get("status", "unknown"),
	]


func _on_search_pressed() -> void:
	var query: String = $Search/SearchInput.text.strip_edges()
	var actors: Array = await RpgActor.search_actors(query)
	if actors.is_empty():
		results_label.text = "No actors found for \"%s\"" % [query]
		return
	var lines: PackedStringArray = []
	for actor in actors:
		if actor is Dictionary:
			lines.append("%s (%s)" % [actor.get("displayName", actor.get("handle", "?")), actor.get("handle", "?")])
	results_label.text = "\n".join(lines)
