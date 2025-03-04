#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
CertifEye - AD CS Abuse Detection Console Application
Author: glides <glid3s@protonmail.com>
Version: 0.9.3

This script provides a console application for detecting potential abuses of Active Directory Certificate Services.
"""

import sys
import argparse
from prompt_toolkit import PromptSession
from prompt_toolkit.shortcuts import CompleteStyle
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.styles import Style
from prompt_toolkit.lexers import Lexer

# Import command modules
import prune_data
import detect_abuse
import generate_synthetic_data
import train_model

# Import utility functions
from certifeye_utils import print_banner, get_logger, load_config

# Import command modules
from train_model import get_parser as train_model_get_parser, main as train_model_main
from generate_synthetic_data import get_parser as gen_data_get_parser, main as gen_data_main
from detect_abuse import get_parser as detect_abuse_get_parser, main as detect_abuse_main
from prune_data import get_parser as prune_data_get_parser, main as prune_data_main



# Initialize logger
logger = get_logger('CertifEye')

# List of available commands and their arguments
COMMANDS = ['detect_abuse', 'generate_synthetic_data', 'prune_data', 'train_model', 'exit', 'help']
COMMAND_ARGUMENTS = {
    'detect_abuse': [
        ('-v', 'Enable verbose output'),
        ('-r', 'Redact sensitive information from output'),
        ('-f', 'Show features used for detection'),
        ('-i', 'Request ID(s) to analyze as comma-separated list'),
    ],
    'generate_synthetic_data': [
        ('-tr', 'Number of training records'),
        ('-ta', 'Number of training abuse cases'),
        ('-at', 'Anomalies in training data'),
        ('-dr', 'Number of detection records'),
        ('-da', 'Number of detection abuse cases'),
        ('-ad', 'Anomalies in detection data'),
        ('-v', 'Enable verbose output'),
        ('-u', 'Update config with generated data')
    ],
    'prune_data': [
        ('-s', 'Sample size of normal requests'),
        ('-v', 'Enable verbose output')
    ],
    'train_model': [
        ('-v', 'Enable verbose output')
    ],
}

# Define styles
style = Style.from_dict({
    # Styles for the prompt
    'prompt':        '#ffffff bold',  # White
    'cyan':          '#00ffff bold',  # Cyan
    'yellow':        '#ffff00 bold',  # Yellow
    'command-teal': '#008888 bold',
    'command-green': 'ansigreen bold',
    'command-red': 'ansired bold',
    'args':          'ansimagenta',
    # Autocomplete styles
    'completion-menu.completion': 'bg:#008888 #ffffff',
    'completion-menu.completion.current': 'bg:#00aaaa #000000',
    'completion-menu.meta.completion': 'bg:#004444 #ffffff',
    'completion-menu.meta.completion.current': 'bg:#006666 #ffffff', 
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
                            # Handle both tuple and string arguments
                            if isinstance(arg, tuple):
                                arg_name = arg[0]  # Extract just the argument name
                                display_meta = arg[1]  # Keep help text
                            else:
                                arg_name = arg
                                display_meta = None
                            
                            yield Completion(
                                arg_name, 
                                start_position=0,
                                display_meta=display_meta
                            )
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
                        # Handle both tuple and string args
                        if isinstance(arg, tuple):
                            arg_name = arg[0]
                        else:
                            arg_name = arg
                        
                        if arg_name.startswith(last_arg):
                            display_meta = arg[1] if isinstance(arg, tuple) else None
                            yield Completion(
                                arg_name, 
                                start_position=start_position,
                                display_meta=display_meta
                            )

class CommandLexer(Lexer):
    def lex_document(self, document):
        def get_line(i):
            text = document.lines[i]
            tokens = []
            pos = 0  # Position in the text
            index = 0  # Word index

            while pos < len(text):
                if text[pos].isspace():
                    # Collect all whitespace
                    space = ''
                    while pos < len(text) and text[pos].isspace():
                        space += text[pos]
                        pos += 1
                    tokens.append(('', space))
                else:
                    # Collect the next word
                    start_pos = pos
                    while pos < len(text) and not text[pos].isspace():
                        pos += 1
                    word = text[start_pos:pos]

                    # Determine token class based on position and content
                    if index == 0:
                        # First word: command
                        if word == 'exit':
                            tokens.append(('class:command-red', word))
                        elif word == 'help':
                            tokens.append(('class:command-green', word))
                        elif word in COMMANDS:
                            tokens.append(('class:command-teal', word))
                        else:
                            tokens.append(('', word))
                    else:
                        # Subsequent words: arguments
                        tokens.append(('class:args', word))

                    index += 1
            return tokens
        return get_line

def main():
    """
    Main function to run the CertifEye console application.
    """
    print_banner()
    session = PromptSession(
        completer=CertifEyeCompleter(),
        style=style,
        lexer=CommandLexer(),
        complete_style=CompleteStyle.MULTI_COLUMN
    )
    
    while True:
        try:
            # Build the prompt message with the colors
            prompt_message = [
                ('class:prompt', '('),
                ('class:cyan', 'Certif'),
                ('class:yellow', 'Eye'),
                ('class:prompt', ') > '),
            ]
            user_input = session.prompt(prompt_message)

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
