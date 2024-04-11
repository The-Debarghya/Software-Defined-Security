import logging

APP_NAME = __package__.rsplit(".", 1)[-1]


def create_logger(
    app_name,
    log_level=logging.INFO,
    stdout=False,
    syslog_flag=False,
    file=True,
    file_name="sds.log",
):
    """
    create logging object with logging to syslog, file and stdout
    :param app_name app name
    :param log_level logging log level
    :param stdout log to stdout
    :param syslog log to syslog
    :param file log to file
    :return: logging object
    """
    logger = logging.getLogger(app_name)
    logger.setLevel(log_level)

    # set log format to handlers
    formatter = logging.Formatter(
        "%(name)s - %(asctime)s - %(levelname)s - %(message)s"
    )

    if file and not logger.handlers:
        # create file logger handler
        fh = logging.FileHandler(file_name)
        fh.setLevel(log_level)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    if syslog_flag:
        # create syslog logger handler
        sh = logging.handlers.SysLogHandler(address="/dev/log")
        sh.setLevel(log_level)
        sf = logging.Formatter("%(asctime)s - %(name)s[%(process)d]: %(message)s")
        sh.setFormatter(sf)
        logger.addHandler(sh)

    if stdout:
        # create stream logger handler
        ch = logging.StreamHandler()
        ch.setLevel(log_level)
        ch.setFormatter(formatter)
        logger.addHandler(ch)
    return logger


def logger_call(level, msg, syslog_flag=True, file_name="sds.log"):
    logger = create_logger(
        APP_NAME, log_level=level, syslog_flag=syslog_flag, file_name=file_name
    )
    if level == logging.INFO:
        logger.info(msg)
    elif level == logging.DEBUG:
        logger.debug(msg)
    elif level == logging.WARNING:
        logger.warning(msg)
    elif level == logging.ERROR:
        logger.error(msg)
    elif level == logging.CRITICAL:
        logger.critical(msg)
    else:
        logger.error("Invalid log level")

    logger.propagate = False
