import os

workers = 1
threads = 4
bind = f"0.0.0.0:{os.getenv('PORT', '80')}"
accesslog = "-"
errorlog = "-"
preload_app = True  # load app in master before forking so post_fork sees initialized modules


def post_fork(server, worker):
    import monitor
    import telegram_bot
    monitor.start()
    telegram_bot.start()
