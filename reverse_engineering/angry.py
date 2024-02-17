import angr,claripy,sys

# EDIT THESE
file_name = "./binary"
input_string_size = 32
# 0x400000 is for PIE binaries only
exit_point = 0x400000+0x1371
avoid_point = 0x400000+0x137f

project = angr.Project(file_name, load_options={"auto_load_libs":False})

# Arguments for entry state
input_string = claripy.BVS("input_string", 8 * input_string_size)
argv = [project.filename, input_string]

# Sets entry point, at the main function of the specified binary
entry_state = project.factory.entry_state(args=argv,add_options={angr.sim_options.ZERO_FILL_UNCONSTRAINED_REGISTERS,angr.sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY})
sim = project.factory.simulation_manager(entry_state)

# Executing bruteforce
sim.explore(find=exit_point, avoid=avoid_point)
if sim.found: 
    solution = sim.found[0]

    if solution.solver.eval(argv[1]) == 0:
        print(f"[*] Solution found:\n{solution.posix.dumps(sys.stdin.fileno()).decode()}")
    else:
        print(f"[*] Solution found:\n{sim.found[0].solver.eval(argv[1], cast_to=bytes).decode()}")
else: 
    print("[!] FAILED")