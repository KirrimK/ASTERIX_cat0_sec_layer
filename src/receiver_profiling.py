import time
import yappi
import TESLA.main_RFC as m


yappi.set_clock_type("wall")
yappi.start()
m.main()
yappi.stop()
yappi.get_func_stats().print_all()
