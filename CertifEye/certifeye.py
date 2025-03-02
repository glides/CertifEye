#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
CertifEye - AD CS Abuse Detection Console Application
Author: glides <glid3s@protonmail.com>
Version: 0.9.2

This script provides a console application for detecting potential abuses of Active Directory Certificate Services.
"""

import sys
import argparse
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.styles import Style
from prompt_toolkit.lexers import PygmentsLexer
from pygments.lexers.shell import BashLexer

# Import command modules
import prune_data
import detect_abuse
import generate_synthetic_data
import train_model

# Import utility functions
from certifeye_utils import print_banner, get_logger, load_config

# Initialize logger
logger = get_logger('CertifEye')

# List of available commands and their arguments
COMMANDS = ['detect_abuse', 'generate_synthetic_data', 'prune_data', 'train_model', 'exit', 'help']
COMMAND_ARGUMENTS = {
    'detect_abuse': ['-v', '--verbose', '-r', '--redact', '-f', '--show-features', '-i', '--request-id'],
    'generate_synthetic_data': ['-tr', '--train_records', '-ta', '--train_abuses', '-dr', '--detect_records', '-da', '--detect_abuses', '-u', '--update-config', '-v', '--verbose'],
    'prune_data': ['-v', '--verbose', '-s', '--sample-size'],
    'train_model': ['-v', '--verbose'],
}

# Define styles
style = Style.from_dict({
    # Styles for the prompt
    'prompt':        'ansicyan bold',
    'path':          'ansiblue bold',
    'command':       'ansiyellow bold',
    'args':          'ansiwhite',
    # Autocomplete styles
    'completion-menu.completion': 'bg:#008888 #ffffff',
    'completion-menu.completion.current': 'bg:#00aaaa #000000',
})

class CertifEyeCompleter(Completer):
    def get_completions(self, document, complete_event):
        # Get the text before the cursor
        text_before_cursor = document.text_before_cursor

        # Get the current word (may be empty if the cursor is after a space)
        word_before_cursor = document.get_word_before_cursor(WORD=True)
        cursor_position = len(text_before_cursor)

        # Split the text into words
        words = text_before_cursor.strip().split()

        if not words:
            # At the beginning, suggest commands
            for cmd in COMMANDS:
                if cmd.startswith(word_before_cursor):
                    yield Completion(cmd, start_position=-len(word_before_cursor))
        else:
            command = words[0]
            if len(words) == 1:
                if text_before_cursor.endswith(' '):
                    # Command typed with a space; suggest arguments
                    if command in COMMAND_ARGUMENTS:
                        for arg in COMMAND_ARGUMENTS[command]:
                            yield Completion(arg, start_position=0)
                else:
                    # Still typing the command
                    word = word_before_cursor
                    for cmd in COMMANDS:
                        if cmd.startswith(word):
                            yield Completion(cmd, start_position=-len(word))
            else:
                # Typing arguments
                if command in COMMAND_ARGUMENTS:
                    # Get the last argument being typed
                    last_arg = word_before_cursor
                    start_position = -len(last_arg)
                    for arg in COMMAND_ARGUMENTS[command]:
                        if arg.startswith(last_arg):
                            yield Completion(arg, start_position=start_position)
                else:
                    # Command not recognized; suggest commands
                    word = word_before_cursor
                    for cmd in COMMANDS:
                        if cmd.startswith(word):
                            yield Completion(cmd, start_position=-len(word))

def main():
    """
    Main function to run the CertifEye console application.
    """
    print_banner()
    session = PromptSession(completer=CertifEyeCompleter(), style=style)

    while True:
        try:
            # Build the prompt message
            prompt_message = [
                ('class:prompt', '(Certif'),
                ('class:path', 'Eye'),
                ('class:prompt', ') > '),
            ]
            user_input = session.prompt(prompt_message, lexer=PygmentsLexer(BashLexer))

            cmd_parts = user_input.strip().split()
            if not cmd_parts:
                continue
            command = cmd_parts[0]
            args = cmd_parts[1:]

            if command == 'exit':
                confirm_exit = session.prompt("Are you sure you want to exit? (y/n): ")
                if confirm_exit.lower() == 'y':
                    print('Goodbye!')
                    break
                else:
                    continue
            elif command == 'help':
                print("Available commands:")
                for cmd in COMMANDS:
                    print(f"  - {cmd}")
                print("Type a command followed by '--help' for more information.")
                continue
            elif command == 'prune_data':
                try:
                    prune_data.main(args)
                except Exception as e:
                    if '-v' in args or '--verbose' in args:
                        print(f"An error occurred: {e}")
                        logger.error(f"An error occurred: {e}", exc_info=True)
                    else:
                        print(f"An error occurred: {e}. Use -v for more details.")
            elif command == 'detect_abuse':
                try:
                    detect_abuse.main(args)
                except Exception as e:
                    if '-v' in args or '--verbose' in args:
                        print(f"An error occurred: {e}")
                        logger.error(f"An error occurred: {e}", exc_info=True)
                    else:
                        print(f"An error occurred: {e}. Use -v for more details.")
            elif command == 'generate_synthetic_data':
                try:
                    generate_synthetic_data.main(args)
                except Exception as e:
                    if '-v' in args or '--verbose' in args:
                        print(f"An error occurred: {e}")
                        logger.error(f"An error occurred: {e}", exc_info=True)
                    else:
                        print(f"An error occurred: {e}. Use -v for more details.")
            elif command == 'train_model':
                try:
                    train_model.main(args)
                except Exception as e:
                    if '-v' in args or '--verbose' in args:
                        print(f"An error occurred: {e}")
                        logger.error(f"An error occurred: {e}", exc_info=True)
                    else:
                        print(f"An error occurred: {e}. Use -v for more details.")
            else:
                print(f"Unknown command: {command}")
                print("Type 'help' to see the list of available commands.")
        except KeyboardInterrupt:
            confirm_exit = session.prompt("\nDo you want to exit? (y/n): ")
            if confirm_exit.lower() == 'y':
                print("Exiting gracefully.")
                break
            else:
                continue
        except EOFError:
            print('Goodbye!')
            break
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}", exc_info=True)
            print(f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    main()
