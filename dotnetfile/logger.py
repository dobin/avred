"""
Part of dotnetfile

Copyright (c) 2016, 2021-2022 - Bob Jung, Yaron Samuel, Dominik Reichel
"""

import logging


def initialize_logging(logger_name: str, level: int = logging.DEBUG) -> logging.Logger:
    logging_level = level
    curr_logger = logging.getLogger(logger_name)

    if not curr_logger.hasHandlers():
        curr_logger.setLevel(logging_level)

        formatter = logging.Formatter(
            '%(levelname)s - %(process)d - %(asctime)s - %(filename)s - %(lineno)d - %(message)s')

        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging_level)
        console_handler.setFormatter(formatter)
        curr_logger.addHandler(console_handler)
        curr_logger.propagate = False

    return curr_logger


def get_logger(logger_name: str, level: int = logging.DEBUG) -> logging.Logger:
    return initialize_logging(logger_name, level)
