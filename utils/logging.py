import logging

def setup_logger():
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        handlers=[logging.FileHandler("app.log"), logging.StreamHandler()])
    return logging.getLogger("app_logger")
