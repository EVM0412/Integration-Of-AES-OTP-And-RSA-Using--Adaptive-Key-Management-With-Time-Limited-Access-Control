


def read_nth_line(filename):
  f1=open("keyno.txt","r")
  n=int(f1.readline())%50
  print(n)
  f1.close()
  with open(filename, "r") as f:
    for i, line in enumerate(f):
      if i == n:
        f1=open("keyno.txt","w")
        f1.write(str(i+1))
        f1.close()
        return line
    return None

