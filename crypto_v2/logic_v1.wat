;; logic_v1.wat
;; Implements: get_state(key) -> value, set_state(key, value)
(module
  ;; Import host functions (provided by proxy)
  (import "env" "get_state" (func $get_state (param i32 i32) (result i32)))
  (import "env" "set_state" (func $set_state (param i32 i32 i32)))
  (import "env" "log"       (func $log (param i32 i32)))

  ;; Memory: 1 page = 64KB
  (memory (export "memory") 1)
  (export "malloc" (func $malloc))
  (export "free"   (func $free))

  ;; Simple malloc (linear)
  (global $heap_ptr (mut i32) (i32.const 1024))
  (func $malloc (param $size i32) (result i32)
    (local $ptr i32)
    local.get $size
    i32.const 16
    i32.add
    i32.const -16
    i32.and
    local.set $size

    global.get $heap_ptr
    local.set $ptr
    global.get $heap_ptr
    local.get $size
    i32.add
    global.set $heap_ptr
    local.get $ptr
  )

  (func $free (param $ptr i32))

  ;; Helper: copy string to memory
  (func $strcpy (param $dst i32) (param $src i32) (param $len i32)
    (local $i i32)
    (local.set $i (i32.const 0))
    (loop $loop
      local.get $i
      local.get $len
      i32.ge_u
      if
        return
      end
      local.get $dst
      local.get $i
      i32.add
      local.get $src
      local.get $i
      i32.add
      i32.load8_u
      i32.store8
      local.get $i
      i32.const 1
      i32.add
      local.set $i
      br $loop
    )
  )

  ;; Exported: get_balance(address) -> balance
  (func (export "get_balance") (param $addr_ptr i32) (param $addr_len i32) (result i32)
    (local $key_ptr i32)
    (local $val_ptr i32)
    (local $val_len i32)

    ;; key = "balance:" + address
    i32.const 8
    call $malloc
    local.set $key_ptr
    local.get $key_ptr
    i32.const 0x65636e61 ;; "bal" reversed
    i32.store
    local.get $key_ptr
    i32.const 4
    i32.add
    i32.const 0x3a656c61 ;; "ance" + ":"
    i32.store

    local.get $key_ptr
    i32.const 8
    i32.add
    local.get $addr_ptr
    local.get $addr_len
    call $strcpy

    ;; Call host
    local.get $key_ptr
    i32.const 8
    local.get $addr_len
    i32.add
    call $get_state
    local.set $val_len
    local.get $val_len
    if
      local.get $val_len
      i32.const 4
      i32.eq
      if
        local.get $val_ptr
        i32.load
      else
        i32.const 0
      end
    else
      i32.const 0
    end
  )

  ;; Exported: set_balance(address, balance)
  (func (export "set_balance") (param $addr_ptr i32) (param $addr_len i32) (param $balance i32)
    (local $key_ptr i32)
    (local $val_ptr i32)

    i32.const 8
    call $malloc
    local.set $key_ptr
    local.get $key_ptr
    i32.const 0x65636e61
    i32.store
    local.get $key_ptr
    i32.const 4
    i32.add
    i32.const 0x3a656c61
    i32.store

    local.get $key_ptr
    i32.const 8
    i32.add
    local.get $addr_ptr
    local.get $addr_len
    call $strcpy

    ;; value = balance (i32)
    i32.const 4
    call $malloc
    local.set $val_ptr
    local.get $val_ptr
    local.get $balance
    i32.store

    local.get $key_ptr
    i32.const 8
    local.get $addr_len
    i32.add
    local.get $val_ptr
    i32.const 4
    call $set_state
  )

  ;; init
  (func $init
    i32.const 0
    i32.const 7
    call $log
  )
  (start $init)
)