extends Control

const OPTION_COUNT := 4

@onready var post_label: Label = $Layout/Post
@onready var options_box: VBoxContainer = $Layout/Options
@onready var result_label: Label = $Layout/Result
@onready var next_button: Button = $Layout/Next

var _answer := ""
var _answered := false


func _ready() -> void:
	next_button.pressed.connect(_new_round)
	_new_round()


func _new_round() -> void:
	for child in options_box.get_children():
		child.queue_free()
	result_label.text = ""
	next_button.disabled = true
	_answered = false

	var authors := GameState.authors()
	_answer = authors.pick_random()
	var texts: Array = GameState.posts_by_did[_answer]
	post_label.text = texts.pick_random()

	var others := authors.duplicate()
	others.erase(_answer)
	others.shuffle()
	var choices: Array[String] = [_answer]
	choices.append_array(others.slice(0, OPTION_COUNT - 1))
	choices.shuffle()

	for did in choices:
		var button := Button.new()
		button.text = GameState.display_name(did)
		button.pressed.connect(_on_option_pressed.bind(did))
		options_box.add_child(button)


func _on_option_pressed(did: String) -> void:
	if _answered:
		return
	_answered = true
	if did == _answer:
		result_label.text = "Correct! It was %s" % GameState.display_name(_answer)
	else:
		result_label.text = "Wrong. It was %s" % GameState.display_name(_answer)
	next_button.disabled = false
