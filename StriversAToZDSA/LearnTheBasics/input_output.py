class Solution:
    def printNumber(self):
        n = int(input())
        print(n)
        print(id(self))
s = Solution()
s.printNumber()
Solution.printNumber(s)
print(id(s))
print(Solution.__dict__)
print(s.__dict__)
print(id(Solution))
print(s.printNumber)