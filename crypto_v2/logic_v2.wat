;; logic_v2.wat
;; Features:
;; - transfer(from, to, amount)
;; - get_balance(addr) -> u64
;; - emit event: "transfer:<from>:<to>:<amount>"
(module
  (import "env" "get_state" (func $get_state (param i32 i32) (result i32)))
  (import "env" "set_state" (func $set_state (param i32 i32 i32)))
  (import "env" "log"       (func $log (param i32 i32)))

  (memory (export "memory") 2)  ;; 128 KB
  (global $heap (mut i32) (i32.const 1024))

  ;; === MALLOC ===
  (func $malloc (param $size i32) (result i32)
    (local $ptr i32)
    local.get $size
    i32.const 15
    i32.add
    i32.const -16
    i32.and
    local.set $size
    global.get $heap
    local.set $ptr
    global.get $heap
    local.get $size
    i32.add
    global.set $heap
    local.get $ptr
  )

  ;; === STRING HELPERS ===
  (func $memcpy (param $dst i32) (param $src i32) (param $len i32)
    (local $i i32)
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

  (func $strlen (param $ptr i32) (result i32)
    (local $len i32)
    (loop $loop
      local.get $ptr
      local.get $len
      i32.add
      i32.load8_u
      i32.eqz
      if
        local.get $len
        return
      end
      local.get $len
      i32.const 1
      i32.add
      local.set $len
      br $loop
    )
  )

  ;; === KEY BUILDERS ===
  (func $make_balance_key (param $addr i32) (param $addr_len i32) (result i32 i32)
    (local $key i32)
    i32.const 16
    call $malloc
    local.set $key
    local.get $key
    i32.const 0x636c6162  ;; "bal"
    i32.store
    local.get $key
    i32.const 4
    i32.add
    i32.const 0x3a65636e  ;; "ance:"
    i32.store
    local.get $key
    i32.const 8
    i32.add
    local.get $addr
    local.get $addr_len
    call $memcpy
    local.get $key
    i32.const 8
    local.get $addr_len
    i32.add
  )

  ;; === GET BALANCE ===
  (func (export "get_balance") (param $addr i32) (param $addr_len i32) (result i64)
    (local $key i32) (local $key_len i32) (local $val_len i32)
    (local $val_ptr i32) (local $balance i64)

    local.get $addr
    local.get $addr_len
    call $make_balance_key
    local.set $key_len
    local.set $key

    local.get $key
    local.get $key_len
    call $get_state
    local.set $val_len
    local.get $val_len
    i32.const 8
    i32.ne
    if
      i64.const 0
      return
    end

    local.get $val_len
    call $malloc
    local.set $val_ptr
    local.get $key
    local.get $key_len
    call $get_state
    drop
    local.get $val_ptr
    i64.load
    local.set $balance
    local.get $balance
  )

  ;; === SET BALANCE ===
  (func $set_balance (param $addr i32) (param $addr_len i32) (param $amount i64)
    (local $key i32) (local $key_len i32) (local $val_ptr i32)
    local.get $addr
    local.get $addr_len
    call $make_balance_key
    local.set $key_len
    local.set $key

    i32.const 8
    call $malloc
    local.set $val_ptr
    local.get $val_ptr
    local.get $amount
    i64.store

    local.get $key
    local.get $key_len
    local.get $val_ptr
    i32.const 8
    call $set_state
    drop
  )

  ;; === SAFE SUB ===
  (func $safe_sub (param $a i64) (param $b i64) (result i64)
    local.get $a
    local.get $b
    i64.lt_u
    if
      i64.const 0
      return
    end
    local.get $a
    local.get $b
    i64.sub
  )

  ;; === EMIT EVENT ===
  (func $emit_transfer (param $from i32) (param $from_len i32) (param $to i32) (param $to_len i32) (param $amount i64)
    (local $msg i32) (local $pos i32) (local $amt_str i32)
    ;; Allocate: "transfer:from:to:amount"
    i32.const 128
    call $malloc
    local.set $msg

    ;; "transfer:"
    local.get $msg
    i32.const 0x7265766e
    i32.store
    local.get $msg
    i32.const 4
    i32.add
    i32.const 0x3a666f72
    i32.store
    local.set $pos
    i32.const 9
    local.set $pos

    ;; from
    local.get $msg
    local.get $pos
    i32.add
    local.get $from
    local.get $from_len
    call $memcpy
    local.get $pos
    local.get $from_len
    i32.add
    local.set $pos
    local.get $msg
    local.get $pos
    i32.add
    i32.const 58  ;; ':'
    i32.store8
    local.get $pos
    i32.const 1
    i32.add
    local.set $pos

    ;; to
    local.get $msg
    local.get $pos
    i32.add
    local.get $to
    local.get $to_len
    call $memcpy
    local.get $pos
    local.get $to_len
    i32.add
    local.set $pos
    local.get $msg
    local.get $pos
    i32.add
    i32.const 58
    i32.store8
    local.get $pos
    i32.const 1
    i32.add
    local.set $pos

    ;; amount (u64 -> decimal string)
    local.get $amount
    call $u64_to_str
    local.set $amt_str
    local.get $amt_str
    call $strlen
    local.set $amt_len

    local.get $msg
    local.get $pos
    i32.add
    local.get $amt_str
    local.get $amt_len
    call $memcpy

    ;; log
    local.get $msg
    local.get $pos
    local.get $amt_len
    i32.add
    call $log
  )

  (func $u64_to_str (param $val i64) (result i32)
    (local $buf i32) (local $i i32) (local $digit i32)
    i32.const 24
    call $malloc
    local.set $buf
    local.get $buf
    i32.const 23
    i32.add
    i32.const 0
    i32.store8

    (loop $loop
      local.get $val
      i64.const 0
      i64.eq
      if
        local.get $buf
        local.get $i
        i32.add
        return
      end
      local.get $val
      i64.const 10
      i64.rem_u
      i32.wrap_i64
      local.set $digit
      local.get $buf
      i32.const 23
      local.get $i
      i32.sub
      i32.add
      local.get $digit
      i32.const 48
      i32.add
      i32.store8
      local.get $i
      i32.const 1
      i32.add
      local.set $i
      local.get $val
      i64.const 10
      i64.div_u
      local.set $val
      br $loop
    )
    local.get $buf
    i32.const 23
    local.get $i
    i32.sub
    i32.add
  )

  ;; === TRANSFER ===
  (func (export "transfer") (param $from i32) (param $from_len i32) (param $to i32) (param $to_len i32) (param $amount i64)
    (local $from_bal i64) (local $new_from i64)

    ;; Load from balance
    local.get $from
    local.get $from_len
    call $get_balance
    local.set $from_bal

    ;; Check overflow
    local.get $from_bal
    local.get $amount
    call $safe_sub
    local.set $new_from
    local.get $new_from
    local.get $from_bal
    i64.eq
    if
      ;; Insufficient funds
      return
    end

    ;; Update from
    local.get $from
    local.get $from_len
    local.get $new_from
    call $set_balance

    ;; Update to
    local.get $to
    local.get $to_len
    call $get_balance
    local.get $amount
    i64.add
    local.get $to
    local.get $to_len
    call $set_balance

    ;; Emit event
    local.get $from
    local.get $from_len
    local.get $to
    local.get $to_len
    local.get $amount
    call $emit_transfer
  )

  ;; === INIT ===
  (func $init
    ;; Set initial supply to admin
    (call $set_balance
      (i32.const 0)   ;; "admin" string at offset 0
      (i32.const 5)
      (i64.const 1000000000000)  ;; 1T tokens
    )
  )
  (start $init)

  ;; === DATA SECTION ===
  (data (i32.const 0) "admin")
)