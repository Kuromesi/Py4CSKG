import matplotlib.pyplot as plt
import pandas as pd

plt.rcParams['font.sans-serif'] = ['Microsoft YaHei']
plt.rcParams['font.size'] = 20
def plot_memory():

    x = [10, 100, 300, 700, 1000, 3000, 5000, 7000, 10000, 15000, 20000]
    memory = [0, 792, 3168, 5016, 5260, 26664, 38968, 48932, 76076, 113544, 146040]
    plt.figure(figsize=(8, 6))
    plt.plot(x, memory, marker='o', linestyle='-', color='b')
    plt.xlabel('网络节点数')
    plt.ylabel('内存消耗 (bytes)')
    plt.grid(True)
    plt.tight_layout()
    plt.savefig("memory.png", dpi=500)
    plt.show()

def plot_attack_graph_time():
    # x = [10, 100, 300, 700, 1000, 3000, 5000, 7000, 10000, 15000, 20000]
    # y = [0.00032401084899902344, 0.003451824188232422, 0.0072939395904541016, 0.047264814376831055, 0.05440163612365723, 0.1615619659423828, 0.28695154190063477, 0.46365785598754883, 0.7091331481933594, 1.34610915184021, 1.8551490306854248]
    x = [100, 1000, 3000, 5000, 7000, 9000, 11000, 13000, 15000, 17000, 19000, 20000]
    y = [0.003002166748046875, 0.04111981391906738, 0.15100643634796143, 0.26891064643859863, 0.41330931186676023, 0.5782417058944702, 0.7442359924316406, 0.8887013673782349, 1.1206831693649293, 1.295570158958435, 1.6570986747741698, 1.710800290107727]
    plt.figure(figsize=(10, 8))
    plt.plot(x, y, marker='o', linestyle='-', color='b')
    plt.xlabel('网络节点数')
    plt.ylabel('运行时间 (s)')
    plt.grid(True)
    plt.tight_layout()
    plt.savefig("attack_graph_time.png", dpi=500)
    plt.show()

def plot_attack_path_time():
    # x = [10, 100, 300, 700, 1000, 3000, 5000, 7000, 10000, 15000, 20000]
    # y = [9.050369262695313e-05, 0.0002378225326538086, 0.0002976655960083008, 0.00029294490814208985, 0.00047032833099365235, 0.0010066032409667969, 0.0015583515167236328, 0.002251935005187988, 0.0027991294860839843, 0.006413769721984863, 0.03056497573852539]
    x = [100, 1000, 3000, 5000, 7000, 9000, 11000, 13000, 15000, 17000, 19000, 20000]
    y = [0.00015374422073364258, 0.0005534052848815918, 0.0009964418411254883, 0.0019069242477416993, 0.002433798313140869, 0.0028776073455810546, 0.003753204345703125, 0.00403771162033081, 0.004932050704956055, 0.007560615539550781, 0.009774432182312012, 0.011056378364562989]
    plt.figure(figsize=(10, 8))
    plt.plot(x, y, marker='o', linestyle='-', color='b')
    plt.xlabel('网络节点数')
    plt.ylabel('运行时间 (s)')
    plt.grid(True)
    plt.tight_layout()
    plt.savefig("attack_path_time.png", dpi=500)
    plt.show()

def plot_total():
    x = [10, 100, 300, 700, 1000, 3000, 5000, 7000, 10000, 15000, 20000]
    time = [0.00032401084899902344, 0.003451824188232422, 0.0072939395904541016, 0.047264814376831055, 0.05440163612365723, 0.1615619659423828, 0.28695154190063477, 0.46365785598754883, 0.7091331481933594, 1.34610915184021, 1.8551490306854248]
    memory = [0, 792, 3168, 5016, 5260, 26664, 38968, 48932, 76076, 113544, 146040]
    fig, ax1 = plt.subplots(figsize=(16, 8))
    ax1.set_xlabel('网络节点数量')
    ax1.set_ylabel('运行时间（s）')
    ax1.plot(x, time, marker='o', linestyle='-', color='tab:blue')

    # 创建并绘制右轴（内存消耗）
    ax2 = ax1.twinx()
    ax2.set_ylabel('内存消耗（bytes）')
    ax2.plot(x, memory, marker='s', linestyle='--', color='tab:red')

    # 显示图例
    ax1.legend(['运行时间'], loc='upper left')
    ax2.legend(['内存消耗'], loc='upper right')
    plt.savefig("total.png", dpi=500)
    plt.show()

def to_csv(*args, **kwargs):
    df_dict = {}
    col_name = 0
    for col in args:
        df_dict[str(col_name)] = col
        col_name += 1
    df = pd.DataFrame(df_dict)
    df.to_csv('time.csv', index=False)


if __name__ == "__main__":
    # plot_total()
    # plot_attack_path_time()
    # plot_attack_graph_time()
    time = [100, 1000, 3000, 5000, 7000, 9000, 11000, 13000, 15000, 17000, 19000, 20000]
    time1 = [0.003002166748046875, 0.04111981391906738, 0.15100643634796143, 0.26891064643859863, 0.41330931186676023, 0.5782417058944702, 0.7442359924316406, 0.8887013673782349, 1.1206831693649293, 1.295570158958435, 1.6570986747741698, 1.710800290107727]
    time2 = [0.00015374422073364258, 0.0005534052848815918, 0.0009964418411254883, 0.0019069242477416993, 0.002433798313140869, 0.0028776073455810546, 0.003753204345703125, 0.00403771162033081, 0.004932050704956055, 0.007560615539550781, 0.009774432182312012, 0.011056378364562989]
    to_csv(time, time1, time2)