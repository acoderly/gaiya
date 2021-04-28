from gaiya.malware_family import MalwareFamily

mf = MalwareFamily()
mf.initialize()
obj = mf.get("dofloo")
obj.run()
