def printDebug(fn):
  def inner(*args, **kwargs):
    #print "CHRIS call %s with %s %s"%(fn.__name__, args, kwargs)
    return fn(*args, **kwargs)
  return inner
