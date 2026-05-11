# BeaconFlow Execution Report

## Summary

- Raw target events: 152
- Compressed events: 144
- Unique blocks: 111
- Unique transitions: 143
- Functions seen: 46
- Truncated: False
- Focus function: <none>

## Diagnostics

- Skipped non-target module events: 7588
- Unmapped function events: 0
- Unmapped basic-block events: 0

## AI Guidance

- Use flow as the observed path, not as a full CFG.
- Prioritize blocks in execution_spine, branch_points, join_points, and dispatcher_candidates.
- Ignore static CFG regions not present in flow until another input reaches them.
- Dispatcher candidates are heuristic; confirm them in IDA pseudocode or with more inputs.

## User Function Order

mainCRTStartup -> _initterm -> pre_c_init -> .text -> pre_cpp_init -> _initialize_narrow_environment -> _configure_narrow_argv -> tls_callback_0 -> _pei386_runtime_relocator -> malloc -> strlen -> memcpy -> atexit -> _onexit -> _crt_atexit -> main -> printf -> fgets -> strcspn -> check_flag -> puts -> tls_callback_1


## Full Function Order

mainCRTStartup -> __tmainCRTStartup -> _initterm -> pre_c_init -> __set_app_type -> __p__fmode -> __p__commode -> .text -> pre_cpp_init -> __getmainargs -> _initialize_narrow_environment -> _configure_narrow_argv -> __p___argc -> __p___argv -> __p__environ -> _set_new_mode -> tls_callback_0 -> _pei386_runtime_relocator -> __mingw_GetSectionCount -> ___chkstk_ms -> _set_invalid_parameter_handler -> _fpreset -> malloc -> strlen -> memcpy -> __main -> __do_global_ctors -> .text -> __gcc_register_frame -> atexit -> _onexit -> _crt_atexit -> main -> printf -> __acrt_iob_func -> __stdio_common_vfprintf -> fgets -> strcspn -> check_flag -> puts -> .text -> __do_global_dtors -> __gcc_deregister_frame -> tls_callback_1 -> __mingw_TLScallback -> __mingwthr_run_key_dtors.part.0

## Execution Spine Preview

1. `mainCRTStartup:0x1400013f0`
2. `__tmainCRTStartup:0x140001180`
3. `__tmainCRTStartup:0x1400011c0`
4. `__tmainCRTStartup:0x1400011cd`
5. `__tmainCRTStartup:0x1400011e1`
6. `__tmainCRTStartup:0x1400013a0`
7. `_initterm:0x140002a00`
8. `pre_c_init:0x140001010`
9. `pre_c_init:0x14000104b`
10. `pre_c_init:0x1400010c0`
11. `pre_c_init:0x1400010cb`
12. `pre_c_init:0x1400010d2`
13. `pre_c_init:0x1400010df`
14. `pre_c_init:0x14000105a`
15. `pre_c_init:0x1400010b0`
16. `__set_app_type:0x140002a08`
17. `pre_c_init:0x1400010b0`
18. `pre_c_init:0x140001077`
19. `__p__fmode:0x140002980`
20. `pre_c_init:0x140001077`
21. `__p__commode:0x140002978`
22. `pre_c_init:0x140001077`
23. `.text:0x140001660`
24. `pre_c_init:0x140001077`
25. `pre_c_init:0x1400010a8`
26. `__tmainCRTStartup:0x1400013a0`
27. `__tmainCRTStartup:0x1400011f5`
28. `__tmainCRTStartup:0x14000134c`
29. `pre_cpp_init:0x140001130`
30. `__getmainargs:0x140002710`
... 50 more preview blocks omitted from Markdown report

## User Dispatcher Candidates

- `main:0x1400014ea` score=17 hits=5 pred=4 succ=4
- `pre_c_init:0x140001077` score=16 hits=4 pred=4 succ=4
- `_pei386_runtime_relocator:0x140001a60` score=12 hits=3 pred=3 succ=3
- `main:0x140001538` score=12 hits=3 pred=3 succ=3
- `printf:0x140002670` score=12 hits=3 pred=3 succ=3
- `check_flag:0x1400014c7` score=9 hits=3 pred=2 succ=2
- `_onexit:0x1400027f0` score=8 hits=2 pred=2 succ=2
- `atexit:0x140001410` score=8 hits=2 pred=2 succ=2
- `main:0x140001560` score=8 hits=2 pred=2 succ=2
- `pre_c_init:0x1400010b0` score=8 hits=2 pred=2 succ=2
- `pre_cpp_init:0x140001130` score=8 hits=2 pred=2 succ=2
- `check_flag:0x140001450` score=6 hits=3 pred=1 succ=1
- `tls_callback_1:0x140001690` score=6 hits=2 pred=2 succ=1

## All Dispatcher Candidates

- `__getmainargs:0x140002710` score=24 hits=6 pred=6 succ=6
- `__tmainCRTStartup:0x140001223` score=21 hits=6 pred=5 succ=5
- `main:0x1400014ea` score=17 hits=5 pred=4 succ=4
- `pre_c_init:0x140001077` score=16 hits=4 pred=4 succ=4
- `_pei386_runtime_relocator:0x140001a60` score=12 hits=3 pred=3 succ=3
- `main:0x140001538` score=12 hits=3 pred=3 succ=3
- `printf:0x140002670` score=12 hits=3 pred=3 succ=3
- `__tmainCRTStartup:0x140001280` score=9 hits=3 pred=2 succ=2
- `check_flag:0x1400014c7` score=9 hits=3 pred=2 succ=2
- `__mingw_TLScallback:0x1400021c0` score=8 hits=2 pred=2 succ=2
- `__tmainCRTStartup:0x1400012b6` score=8 hits=2 pred=2 succ=2
- `__tmainCRTStartup:0x14000134c` score=8 hits=2 pred=2 succ=2
- `__tmainCRTStartup:0x1400013a0` score=8 hits=2 pred=2 succ=2
- `_onexit:0x1400027f0` score=8 hits=2 pred=2 succ=2
- `atexit:0x140001410` score=8 hits=2 pred=2 succ=2
- `main:0x140001560` score=8 hits=2 pred=2 succ=2
- `pre_c_init:0x1400010b0` score=8 hits=2 pred=2 succ=2
- `pre_cpp_init:0x140001130` score=8 hits=2 pred=2 succ=2
- `check_flag:0x140001450` score=6 hits=3 pred=1 succ=1
- `tls_callback_1:0x140001690` score=6 hits=2 pred=2 succ=1

## User Branch Points

- `pre_c_init:0x140001077` -> `.text:0x140001660`, `__p__commode:0x140002978`, `__p__fmode:0x140002980`, `pre_c_init:0x1400010a8`
- `main:0x1400014ea` -> `__main:0x14000164a`, `fgets:0x140002998`, `main:0x140001538`, `printf:0x140002670`
- `main:0x140001538` -> `check_flag:0x140001450`, `main:0x140001560`, `strcspn:0x140002950`
- `_pei386_runtime_relocator:0x140001a60` -> `___chkstk_ms:0x140002610`, `__mingw_GetSectionCount:0x1400023b0`, `_pei386_runtime_relocator:0x140001a4f`
- `printf:0x140002670` -> `__acrt_iob_func:0x140002970`, `__stdio_common_vfprintf:0x140002988`, `main:0x1400014ea`
- `pre_c_init:0x1400010b0` -> `__set_app_type:0x140002a08`, `pre_c_init:0x140001077`
- `pre_cpp_init:0x140001130` -> `__getmainargs:0x140002710`, `__tmainCRTStartup:0x14000134c`
- `atexit:0x140001410` -> `__do_global_ctors:0x140001600`, `_onexit:0x1400027f0`
- `check_flag:0x1400014c7` -> `check_flag:0x14000149a`, `check_flag:0x1400014de`
- `main:0x140001560` -> `main:0x140001580`, `puts:0x1400029a8`
- `_onexit:0x1400027f0` -> `_crt_atexit:0x1400029e8`, `atexit:0x140001410`

## User Join Points

- `pre_c_init:0x140001077` <- `.text:0x140001660`, `__p__commode:0x140002978`, `__p__fmode:0x140002980`, `pre_c_init:0x1400010b0`
- `main:0x1400014ea` <- `__main:0x14000164a`, `__tmainCRTStartup:0x1400012b6`, `fgets:0x140002998`, `printf:0x140002670`
- `main:0x140001538` <- `check_flag:0x1400014de`, `main:0x1400014ea`, `strcspn:0x140002950`
- `_pei386_runtime_relocator:0x140001a60` <- `___chkstk_ms:0x140002638`, `__mingw_GetSectionCount:0x1400023e0`, `_pei386_runtime_relocator:0x140001a30`
- `printf:0x140002670` <- `__acrt_iob_func:0x140002970`, `__stdio_common_vfprintf:0x140002988`, `main:0x1400014ea`
- `pre_c_init:0x1400010b0` <- `__set_app_type:0x140002a08`, `pre_c_init:0x14000105a`
- `pre_cpp_init:0x140001130` <- `__getmainargs:0x14000276d`, `__tmainCRTStartup:0x14000134c`
- `atexit:0x140001410` <- `__gcc_register_frame:0x140001430`, `_onexit:0x1400027f0`
- `check_flag:0x1400014c7` <- `check_flag:0x140001491`, `check_flag:0x1400014c3`
- `main:0x140001560` <- `main:0x140001538`, `puts:0x1400029a8`
- `tls_callback_1:0x140001690` <- `__mingw_TLScallback:0x14000211c`, `tls_callback_1:0x140001679`
- `_onexit:0x1400027f0` <- `_crt_atexit:0x1400029e8`, `atexit:0x140001410`

## User Loop-Like Edges

- `.text:0x140001660` -> `pre_c_init:0x140001077` hits=1
- `pre_c_init:0x1400010a8` -> `__tmainCRTStartup:0x1400013a0` hits=1
- `_initialize_narrow_environment:0x1400029f0` -> `__getmainargs:0x140002710` hits=1
- `_configure_narrow_argv:0x1400029d0` -> `__getmainargs:0x140002710` hits=1
- `pre_cpp_init:0x140001130` -> `__tmainCRTStartup:0x14000134c` hits=1
- `_pei386_runtime_relocator:0x140001a4f` -> `__tmainCRTStartup:0x140001223` hits=1
- `malloc:0x140002a68` -> `__tmainCRTStartup:0x140001223` hits=1
- `memcpy:0x140002a38` -> `__tmainCRTStartup:0x140001280` hits=1
- `_crt_atexit:0x1400029e8` -> `_onexit:0x1400027f0` hits=1

## Next Steps

- Start with user_dispatcher_candidates and user_branch_points before CRT/runtime-heavy fields.
- Open the top dispatcher candidates and inspect state-variable updates.
- Compare record_flow outputs from multiple inputs to separate real branches from dead flattened CFG edges.
- If a candidate needs value recovery, collect a richer trace with register or memory state.
