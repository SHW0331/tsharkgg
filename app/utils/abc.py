import matplotlib.pyplot as plt

# 데이터
categories = ['A', 'B', 'C', 'D']
values = [10, 15, 7, 12]

# 그래프 생성
plt.figure(figsize=(8, 6))  # 그래프 크기 설정
plt.bar(categories, values, color='skyblue')
plt.title('Bar Chart Example', fontsize=16)
plt.xlabel('Categories', fontsize=12)
plt.ylabel('Values', fontsize=12)
plt.grid(axis='y', linestyle='--', alpha=0.7)

# 그래프 표시
plt.show()
