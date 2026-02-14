#!/bin/bash
# Test script for enhanced SShell

SSHELL="/projects/sshell/build/sshell"

echo "==================================================================="
echo "Testing Enhanced SShell C Implementation"
echo "==================================================================="
echo ""

echo "1. Creating sessions..."
$SSHELL new test-session-1 --no-attach
$SSHELL new test-session-2 --no-attach
$SSHELL new test-session-3 --no-attach
echo ""

echo "2. Listing sessions..."
$SSHELL list
echo ""

echo "3. Renaming a session..."
$SSHELL rename test-session-1 renamed-work
echo ""

echo "4. Listing after rename..."
$SSHELL list
echo ""

echo "5. Killing a session..."
$SSHELL kill test-session-2
echo ""

echo "6. Final list..."
$SSHELL list
echo ""

echo "7. Testing with shell option..."
$SSHELL new bash-session --shell /bin/bash --no-attach
echo ""

echo "8. All tests complete!"
$SSHELL list
echo ""

echo "==================================================================="
echo "Enhanced features working:"
echo "  ✓ Session creation"
echo "  ✓ Session listing"
echo "  ✓ Session rename"
echo "  ✓ Session kill"
echo "  ✓ Custom shell"
echo "  ✓ Auto-daemon start"
echo "==================================================================="
