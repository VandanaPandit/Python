class Solution:
    def printNumber(self):
        n = int(input())
        print(n)
        print(id(self))
s = Solution()
s.printNumber()
Solution.printNumber(s)
print(id(s))