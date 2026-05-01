import re

class Solution:
    def compareString(self,str1,str2):
        return bool(re.fullmatch(str1, str2, re.IGNORECASE))
    
str1 = input()
str2 = input()

obj = Solution()
if obj.compareString(str1,str2):
    print("Strings are same")
else:
    print("strings are not same")