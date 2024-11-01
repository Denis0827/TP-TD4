import pandas as pd
import matplotlib.pyplot as plt

file_path = 'C:/Users/Denis Wu/Desktop/TP_TD4/datos_experimento.xlsx'  
excel_data = pd.ExcelFile(file_path)
data = excel_data.parse('Sheet1') 

x = data['Enviados']
y_correctos = data['Correctos(%)']
y_delay = data['Delay(%)']
y_corrupcion = data['Corrupcion(%)']
y_perdida = data['Perdida(%)']

plt.figure(figsize=(10, 6))
plt.plot(x, y_correctos, color='b', label='Correctos (%)')
plt.plot(x, y_delay, color='r', label='Delay (%)')
plt.plot(x, y_corrupcion, color='g', label='Corrupción (%)')
plt.plot(x, y_perdida, color='purple', label='Pérdida (%)')

plt.title("Porcentaje de Correctos, Delay, Corrupción y Pérdida (%)")
plt.xlabel("Cantidad de paquetes enviados")
plt.ylabel("Porcentaje (%)")
plt.grid(True)
plt.legend()
plt.show()