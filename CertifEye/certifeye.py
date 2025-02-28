#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
CertifEye - AD CS Abuse Detection Console Application
Author: glides <glid3s@protonmail.com>
Version: 0.9.1

This script provides a console application for detecting potential abuses of Active Directory Certificate Services.
"""

import sys
import logging
import argparse

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.styles import Style

# Import your command modules
import prune_data
import detect_abuse
import generate_synthetic_data
import train_model

from certifeye_utils import print_banner

# Initialize logger
logger = logging.getLogger('CertifEye')
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
formatter = logging.Formatter('%(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# List of available commands
COMMANDS = ['detect_abuse', 'generate_synthetic_data', 'prune_data', 'train_model']

# Create a mapping of commands to their parsers
COMMAND_PARSERS = {
    'prune_data': prune_data.get_parser(),
    'detect_abuse': detect_abuse.get_parser(),
    'generate_synthetic_data': generate_synthetic_data.get_parser(),
    'train_model': train_model.get_parser(),
}

# Define styles
style = Style.from_dict({
    # Styles for the prompt
    'prompt':        'ansiwhite',
    'prompt_cyan':   'ansicyan bold',
    'prompt_yellow': 'ansiyellow bold',
    # Styles for user input
    'command': 'ansiyellow bold',  # Command verbs in yellow
    'args':    'ansiwhite',        # Arguments in white
    'option':  'ansimagenta',      # Options (e.g., --verbose) in magenta
    'error':   'ansired bold',     # Errors in red bold
})

class CommandLexer:
    def __init__(self, commands, command_parsers):
        self.commands = commands
        self.command_parsers = command_parsers

    def lex_document(self, document):
        text = document.text

        def get_line(lineno):
            tokens = []
            import shlex
            try:
                words = shlex.split(text)
            except ValueError:
                words = text.strip().split()

            idx = 0
            while idx < len(text):
                # Handle spaces
                if text[idx].isspace():
                    tokens.append(('class:args', text[idx]))
                    idx += 1
                    continue

                # Get the next word
                start_idx = idx
                while idx < len(text) and not text[idx].isspace():
                    idx += 1
                word = text[start_idx:idx]

                if start_idx == 0:
                    # First word, check if it's a command
                    if word in self.commands:
                        tokens.append(('class:command', word))
                    else:
                        tokens.append(('class:error', word))
                elif word.startswith('-'):
                    # Option
                    tokens.append(('class:option', word))
                else:
                    # Argument
                    tokens.append(('class:args', word))

            return tokens

        return get_line

class CertifEyeCompleter(Completer):
    def get_completions(self, document, complete_event):
        # Get the text before the cursor
        text = document.text_before_cursor

        # Split the text into words and handle quotes
        import shlex
        try:
            words = shlex.split(text)
        except ValueError:
            # If the user has an unclosed quote, treat it as is
            words = text.strip().split()

        # If no words have been entered, suggest command names
        if not words:
            for cmd in COMMANDS:
                yield Completion(cmd, start_position=0)
        elif len(words) == 1:
            # Only provide suggestions if the cursor is at the end of the input
            if document.cursor_position_col == len(text):
                word = words[0]
                for cmd in COMMANDS:
                    if cmd.startswith(word):
                        yield Completion(cmd, start_position=-len(word))
        else:
            # Get the current command
            current_command = words[0]
            if current_command in COMMAND_PARSERS:
                parser = COMMAND_PARSERS[current_command]
                # Get a list of argument strings
                args = []
                for action in parser._actions:
                    for option_string in action.option_strings:
                        args.append(option_string)
                # Get the current argument being typed
                current_arg = words[-1]
                # Only provide suggestions if the cursor is at the end of the input
                if document.cursor_position_col == len(text):
                    for arg in args:
                        if arg.startswith(current_arg):
                            yield Completion(arg, start_position=-len(current_arg))

def main():
    print_banner()
    session = PromptSession()
    lexer = CommandLexer(COMMANDS, COMMAND_PARSERS)
    completer = CertifEyeCompleter()

    while True:
        try:
            prompt_text = [
                ('class:prompt', '('),
                ('class:prompt_cyan', 'Certif'),
                ('class:prompt_yellow', 'Eye'),
                ('class:prompt', ') > '),
            ]
            user_input = session.prompt(prompt_text, lexer=lexer, completer=completer, style=style)
            cmd_parts = user_input.strip().split()
            if not cmd_parts:
                continue
            command = cmd_parts[0]
            args = cmd_parts[1:]

            if command == 'exit':
                print('Goodbye!')
                break
            elif command == 'prune_data':
                prune_data.main(args)
            elif command == 'detect_abuse':
                detect_abuse.main(args)
            elif command == 'generate_synthetic_data':
                generate_synthetic_data.main(args)
            elif command == 'train_model':
                train_model.main(args)
            else:
                print(f"Unknown command: {command}")
                print("Type 'help' to see the list of available commands.")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user. Exiting gracefully.")
            sys.exit(0)
        except EOFError:
            print('Goodbye!')
            break
        except Exception as e:
            print(f"An error occurred: {str(e)}")

if __name__ == '__main__':
    main()
