import tplink
import logging

api = tplink.TPLinkClient('192.168.1.1', log_level = logging.DEBUG)

# Set logout_others to False if you don't want to kick out a logged in user
api.connect('password in plaintext', logout_others = True)

# Print connected clients
print(api.get_client_list())

# Safely logout so others can login
api.logout()
