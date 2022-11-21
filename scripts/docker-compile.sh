set -e
if [ -f "/project/compile" ]; then
    echo "Calling /project/compile"
    /project/compile
else
  echo "Compile file not found at /project/compile"
fi
