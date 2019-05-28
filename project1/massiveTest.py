from subprocess import call

# for i in range(1,100):
#     i = "{}".format(i)
#     call(["./tester", "-w" , "20", "-T", "10","./reliable"])
#
#
# for i in range(1,100):
#     i = "{}".format(i)
#     call(["./tester", "-w" , "30", "-T", "10","./reliable"])
#
# for i in range(1,100):
#     i = "{}".format(i)
#     call(["./tester", "-w" , "40", "-T", "10","./reliable"])
#
# for i in range(1,100):
#     i = "{}".format(i)
#     call(["./tester", "-w" , "50", "-T", "10","./reliable"])
#
# for i in range(1,100):
#     i = "{}".format(i)
#     call(["./tester", "-w" , "10000", "-T", "10","./reliable"])

for i in range(1,50):
    i = "{}".format(i)
    call(["./tester", "-w" , "30","./reliable"])

for i in range(1,50):
    i = "{}".format(i)
    call(["./tester", "-w" , "40","./reliable"])

for i in range(1,50):
    i = "{}".format(i)
    call(["./tester", "-w" , "50","./reliable"])

for i in range(1,50):
    i = "{}".format(i)
    call(["./tester", "-w" , "10000","./reliable"])

print("FINISHED GENERAL TEST")
