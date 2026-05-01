class Solution:
    def stringLength(self,str):
        return len(str)
    
print(__name__)

if __name__=="__main__":
    s = Solution()
    str_input = input("Enter a string and ill give you the length of the string - ")
    print(s.stringLength(str_input))

