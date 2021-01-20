PATH_FILTER=$1
CHANGED_FILES=$(git diff HEAD HEAD~ --name-only)
MATCH_FOUND=0

echo "Checking for file changes..."
for FILE in $CHANGED_FILES
do
  if [[ $FILE == *$PATH_FILTER* ]]; then
    MATCH_FOUND=1
    break
  fi
done

if  [[ $MATCH_FOUND -gt 0 ]]; then
  echo "Changes found for filter '$PATH_FILTER'."  
  echo "##vso[task.setvariable variable=SOURCE_CODE_CHANGED_${1^^};isOutput=true]true"
else
  echo "No Changes found for filter '$PATH_FILTER'."    
  echo "##vso[task.setvariable variable=SOURCE_CODE_CHANGED_${1^^};isOutput=true]false"
fi