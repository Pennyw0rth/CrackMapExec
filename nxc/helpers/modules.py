from nxc.paths import NXC_PATH
from os import makedirs
import logging
import datetime


def create_log_dir(module_name):
    makedirs(f"{NXC_PATH}/logs/{module_name}", exist_ok=True)

def create_loot_dir(module_name):
    makedirs(f"{NXC_PATH}/loot/{module_name}", exist_ok=True)
    
def generate_module_log_file(module_name):
    create_log_dir(module_name)
    return f"{NXC_PATH}/logs/{module_name}/{datetime.now().strftime('%Y-%m-%d')}.log"
    
def create_module_logger(module_name):
    log_file = generate_module_log_file(module_name)
    module_logger = logging.getLogger(module_name)
    module_logger.propagate = False
    module_logger.setLevel(logging.INFO)
    module_file_handler = logging.FileHandler(log_file)
    module_file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    module_logger.addHandler(module_file_handler)
    return module_logger

def add_loot_data(module_name, filename, data):
    create_loot_dir(module_name)
    loot_file = get_loot_data_filepath(module_name, filename)
    with open(loot_file, "a") as file:
        file.write(data)
         
def get_loot_data_filepath(module_name, filename):
    return f"{NXC_PATH}/loot/{module_name}/{filename}"

def get_loot_data_folder(module_name):
    return f"{NXC_PATH}/loot/{module_name}"
