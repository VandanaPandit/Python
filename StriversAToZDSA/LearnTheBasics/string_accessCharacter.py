class Solution:
    def accessCharacter(self, s):
        for i in range(len(s)):
            print(s[i])

if __name__ == "__main__":
    obj = Solution()
    str = "hello world"
    obj.accessCharacter(str)