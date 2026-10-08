# Witness input for the build-time feedback-gate check.
#
# It escapes a closure out of a method frame, which makes mrb_env_unshare()
# pop a non-empty on-stack environment and execute the stack-copy branch at
# src/vm.c:398.  The feedback-gate check asserts that the instrumented binary
# emits the feedback map's block/location IDs for that line when running this
# input; if the map and the binary disagree on IDs, the harness can never
# confirm a target-site hit and the build must fail instead.
$p = nil
GC.interval_ratio = 20

def maker
  x = "A" * 100
  $p = ->{ x }
  i = 0
  while i < 1000
    Object.new
    i += 1
  end
  x = "Z" * 4096
  nil
end

maker

i = 0
while i < 20
  Object.new
  i += 1
end

$p.call.getbyte(0)
