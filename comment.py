# comment.py
# This module defines the `Commentaireia` class, which provides context-based random comments.
# The comments are based on various themes such as "IDLE", "SCANNER", and others, to simulate
# different states or actions within a network scanning and security context. The class uses a 
# shared data object to determine delays between comments and switches themes based on the current 
# state. The `get_commentaire` method returns a random comment from the specified theme, ensuring 
# comments are not repeated too frequently.

import random
import time
import logging
import json
from init_shared import shared_data  
from logger import Logger
import os

logger = Logger(name="comment.py", level=logging.DEBUG)

class Commentaireia:
    """Provides context-based random comments for ragnar."""
    def __init__(self):
        self.shared_data = shared_data
        self.last_comment_time = 0  # Initialize last_comment_time
        self.comment_delay = random.randint(self.shared_data.comment_delaymin, self.shared_data.comment_delaymax)  # Initialize comment_delay
        self.last_theme = None  # Initialize last_theme
        self.themes = self.load_comments(self.shared_data.commentsfile)  # Load themes from JSON file

    def load_comments(self, commentsfile):
        """Load comments from a JSON file."""
        cache_file = commentsfile + '.cache'

        # Check if a cached version exists and is newer than the original file
        if os.path.exists(cache_file) and os.path.exists(commentsfile) and os.path.getmtime(cache_file) >= os.path.getmtime(commentsfile):
            try:
                with open(cache_file, 'r') as file:
                    comments_data = json.load(file)
                    logger.info("Comments loaded successfully from cache.")
                    return comments_data
            except (FileNotFoundError, json.JSONDecodeError) as e:
                logger.warning(f"Cache file is corrupted or not found: {e}. Loading from the original file.")

        # Load from the original file if cache is not used or corrupted
        try:
            if not os.path.exists(commentsfile):
                logger.error(f"Comments file not found: {commentsfile}")
                return {"IDLE": ["No comments available"]}
                
            with open(commentsfile, 'r', encoding='utf-8') as file:
                comments_data = json.load(file)
                logger.info("Comments loaded successfully from JSON file.")
                
                # Validate that required themes exist
                required_themes = ["IDLE", "NetworkScanner"]
                for theme in required_themes:
                    if theme not in comments_data:
                        logger.warning(f"Required theme '{theme}' not found in comments file")
                        comments_data[theme] = [f"Theme {theme} comments not available"]
                
                # Save to cache
                try:
                    with open(cache_file, 'w', encoding='utf-8') as cache:
                        json.dump(comments_data, cache)
                except Exception as e:
                    logger.warning(f"Could not save comments cache: {e}")
                    
                return comments_data
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Error loading comments from JSON file: {e}")
            return {"IDLE": ["No comments available"], "NetworkScanner": ["Scanning networks..."]}
        except Exception as e:
            logger.error(f"Unexpected error loading comments: {e}")
            return {"IDLE": ["No comments available"], "NetworkScanner": ["Scanning networks..."]}

    def get_commentaire(self, theme):
        """ This method returns a random comment based on the specified theme."""
        current_time = time.time()  # Get the current time in seconds
        if theme != self.last_theme or current_time - self.last_comment_time >= self.comment_delay:  # Check if the theme has changed or if the delay has expired
            self.last_comment_time = current_time   # Update the last comment time
            self.last_theme = theme   # Update the last theme

            if theme not in self.themes: 
                logger.warning(f"The theme '{theme}' is not defined, using the default theme IDLE.")
                theme = "IDLE"

            return random.choice(self.themes[theme])  # Return a random comment based on the specified theme
        else:
            return None
