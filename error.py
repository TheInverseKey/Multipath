import logging
logger = logging.getLogger('errorlog')
logger.setLevel(logging.ERROR)
handler = logging.FileHandler('Error.log')
handler.setLevel(logging.ERROR)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


#Example
logger.error('Something went wrong')
