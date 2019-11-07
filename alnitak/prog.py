
class Error:
	'''
	'''
	def __init__(self, errno, message):
		self.errno = errno
		self.message = message

	def __str__(self):
		return str(self.message)

	def __int__(self):
		return int(self.errno)

