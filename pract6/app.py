"""Запуск настольного приложения: python3 app.py."""
import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText

from crypto import (Generator, decrypt_steps, encrypt_steps, gm_key_steps, hors_key_steps, miller_rabin,
                    prime_steps, probable_prime, solovay_strassen, verify)


def box(parent, title, height=3, editable=False):
    ttk.Label(parent, text=title).pack(anchor='w', pady=(6, 2))
    font = 'TkTextFont' if editable else 'TkFixedFont'
    widget = ScrolledText(parent, height=height, width=45, wrap='char', font=font)
    widget.pack(fill='both', expand=True)
    if not editable:
        widget.configure(state='disabled')
    return widget


def show(widget, value):
    widget.configure(state='normal')
    widget.delete('1.0', 'end')
    widget.insert('1.0', value)
    widget.configure(state='disabled')


def row(parent):
    frame = ttk.Frame(parent)
    frame.pack(fill='x', pady=4)
    return frame


def hex_preview(data):
    suffix = f' …  (всего {len(data)} байт)' if len(data) > 160 else ''
    return data[:160].hex(' ') + suffix


def decimal(text):
    try:
        return int(text.strip())
    except ValueError:
        raise ValueError('Введите целое число десятичными цифрами.') from None


class Window:
    def __init__(self, window, name):
        self.window, self.name = window, name
        window.title(name)
        self.rng = self.private = self.hors = None
        self.peer_n = self.peer_hors = None
        self.outgoing = self.incoming = None
        self.busy = False
        self.samples = []
        self.status = tk.StringVar()
        self.entropy = tk.StringVar(value='Для запуска генератора поводите мышью по полю ниже (0/96).')
        self.key_status = tk.StringVar()
        self.tabs = ttk.Notebook(window)
        self.tabs.pack(fill='both', expand=True, padx=10, pady=(10, 0))
        self.keys = self.tab('Ключи')
        self.out = self.tab('Отправка')
        self.inc = self.tab('Приём')
        self.numbers = self.tab('Простые числа')
        self.build_keys()
        self.build_messages()
        self.build_numbers()
        self.progress = ttk.Progressbar(window, mode='indeterminate')
        self.progress.pack(fill='x', padx=10, pady=(4, 0))
        self.log = box(window, 'Журнал', 3)
        self.log.pack_configure(expand=False, padx=10)
        ttk.Label(window, textvariable=self.status, wraplength=510).pack(anchor='w', padx=10, pady=6)
        self.refresh_keys()

    def tab(self, title):
        frame = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(frame, text=title)
        return frame

    def note(self, message):
        self.status.set(message)
        self.log.configure(state='normal')
        self.log.insert('end', message + '\n')
        self.log.see('end')
        self.log.configure(state='disabled')

    def button(self, frame, label, action):
        def click():
            if self.busy:
                self.status.set('Идёт вычисление. Дождитесь результата.')
                return
            try:
                action()
            except ValueError as error:
                self.note(str(error))
        ttk.Button(frame, text=label, command=click).pack(side='left', padx=(0, 4), pady=2)

    def calculate(self, label, steps, finish):
        if self.rng is None:
            raise ValueError('Сначала подготовьте генератор на вкладке «Ключи».')
        self.busy = True
        self.status.set(label + '…')
        self.progress.start(90)

        def advance():
            try:
                next(steps)
            except StopIteration as result:
                self.busy = False
                self.progress.stop()
                try:
                    finish(result.value)
                except ValueError as error:
                    self.note(str(error))
            except ValueError as error:
                self.busy = False
                self.progress.stop()
                self.note(str(error))
            else:
                self.window.after(1, advance)
        self.window.after(1, advance)

    def build_keys(self):
        ttk.Label(self.keys, textvariable=self.entropy).pack(anchor='w')
        area = tk.Canvas(self.keys, height=52, bg='#dcebf2', highlightthickness=0)
        area.pack(fill='x', pady=(3, 8))

        def motion(event):
            if self.rng is not None:
                return
            self.samples.append(f'{event.x},{event.y},{event.time};')
            count = len(self.samples)
            self.entropy.set(f'Для запуска генератора поводите мышью по полю ниже ({count}/96).')
            if count == 96:
                self.rng = Generator((self.name + ''.join(self.samples)).encode())
                self.samples.clear()
                self.entropy.set('Генератор готов')
                for button in buttons.winfo_children():
                    button.state(['!disabled'])
                purpose = 'подписи' if self.name == 'Отправитель' else 'шифрования'
                self.note(f'Генератор готов. Создайте ключ {purpose}.')
        area.bind('<Motion>', motion)
        buttons = row(self.keys)
        actions = [('Создать ключ подписи', self.new_hors), ('Создать ключ шифрования', self.new_gm)]
        if self.name == 'Получатель':
            actions.reverse()
        for label, action in actions:
            self.button(buttons, label, action)
        for button in buttons.winfo_children():
            button.state(['disabled'])
        self.button(row(self.keys), 'Передать открытые ключи', self.exchange)
        ttk.Label(self.keys, textvariable=self.key_status, justify='left').pack(anchor='w', pady=8)
        self.key_info = box(self.keys, 'Открытые параметры', 4)
        self.button(row(self.keys), 'Показать закрытые параметры', self.reveal)
        self.private_info = box(self.keys, 'Закрытые параметры', 2)

    def refresh_keys(self):
        own, received = [], []
        if self.private:
            own.append('шифрование (GM)')
        if self.hors:
            own.append('подпись (HORS)' if self.hors.secret else 'подпись (ключ использован)')
        if self.peer_n:
            received.append('шифрование')
        if self.peer_hors:
            received.append('подпись')
        self.key_status.set('Свои ключи: ' + (', '.join(own) or 'пока нет') +
                            '\nПолученные ключи: ' + (', '.join(received) or 'пока нет'))
        lines = []
        if self.private:
            lines.append(f'GM, n (2048 бит) = {self.private[0] * self.private[1]}')
        if self.hors:
            lines.append('HORS, 4096 хешей. Первый: ' + self.hors.public[0].hex())
        show(self.key_info, '\n'.join(lines))
        show(self.private_info, '')

    def reveal(self):
        lines = []
        if self.private:
            lines.extend((f'p = {self.private[0]}', f'q = {self.private[1]}'))
        if self.hors and self.hors.secret:
            lines.append('Первый из 4096 секретов HORS: ' + self.hors.secret[0].hex())
        show(self.private_info, '\n'.join(lines) or 'Доступных закрытых параметров нет.')

    def new_gm(self):
        def ready(key):
            self.private = key
            self.refresh_keys()
            self.note('Готова пара GM. Передайте открытый ключ второй стороне.')
        self.calculate('Поиск двух 1024-битных простых', gm_key_steps(self.rng), ready)

    def new_hors(self):
        def ready(key):
            self.hors = key
            self.refresh_keys()
            self.note('Готов ключ HORS на одну подпись. Передайте открытый ключ.')
        self.calculate('Создание ключа HORS', hors_key_steps(self.rng), ready)

    def exchange(self):
        if not (self.private or self.hors):
            raise ValueError('Сначала создайте свой ключ.')
        if self.peer.busy:
            raise ValueError('Вторая сторона занята вычислением. Повторите передачу позже.')
        if self.private:
            self.peer.peer_n = self.private[0] * self.private[1]
        if self.hors:
            self.peer.peer_hors = self.hors.public
        self.peer.refresh_keys()
        self.peer.note('Получены открытые ключи второй стороны.')
        if self.name == 'Отправитель' and self.hors and self.peer_n:
            self.note('Ключи переданы. Откройте вкладку «Отправка».')
        else:
            self.note('Открытые ключи переданы.')

    def build_messages(self):
        self.source = box(self.out, 'Сообщение (до 128 байт UTF-8)', 4, editable=True)
        buttons = row(self.out)
        self.button(buttons, 'Зашифровать', self.encrypt)
        self.button(buttons, 'Подписать', self.sign)
        self.button(buttons, 'Передать', self.send)
        self.cipher = box(self.out, 'Шифротекст, hex')
        self.signature = box(self.out, 'Подпись, hex')

        self.received = box(self.inc, 'Полученный шифротекст, hex')
        self.received_sig = box(self.inc, 'Подпись, hex')
        buttons = row(self.inc)
        self.button(buttons, 'Проверить подпись', self.check)
        self.button(buttons, 'Расшифровать', self.decrypt)
        self.button(row(self.inc), 'Изменить один блок', self.tamper)
        self.plain = box(self.inc, 'Расшифрованное сообщение')

    def encrypt(self):
        data = self.source.get('1.0', 'end-1c').encode()
        if not 1 <= len(data) <= 128:
            raise ValueError('Введите сообщение длиной от 1 до 128 байт UTF-8.')
        n = self.peer_n
        if n is None:
            raise ValueError('Получите открытый ключ GM второй стороны.')
        def ready(packet):
            self.outgoing = (data, n, packet, None, None)
            show(self.cipher, hex_preview(packet))
            show(self.signature, '')
            self.note(f'Зашифровано {len(data)} байт. Теперь подпишите пакет.')
        self.calculate('Шифрование', encrypt_steps(data, n, self.rng), ready)

    def current_packet(self):
        if not self.outgoing or self.source.get('1.0', 'end-1c').encode() != self.outgoing[0]:
            raise ValueError('Сначала зашифруйте текущий текст.')
        if self.peer_n != self.outgoing[1]:
            raise ValueError('Ключ получателя обновился. Зашифруйте сообщение заново.')
        return self.outgoing

    def sign(self):
        data, n, packet, _, _ = self.current_packet()
        if self.hors is None:
            raise ValueError('Создайте свою пару HORS.')
        signature = self.hors.sign(packet)
        self.outgoing = (data, n, packet, signature, self.hors.public)
        show(self.signature, hex_preview(signature))
        self.refresh_keys()
        self.note('Пакет подписан. Ключ HORS использован.')

    def send(self):
        _, n, packet, signature, signer = self.current_packet()
        if signature is None:
            raise ValueError('Сначала подпишите шифротекст.')
        if self.peer.busy:
            raise ValueError('Получатель занят вычислением. Повторите передачу позже.')
        if self.peer.peer_hors != signer:
            raise ValueError('Передайте открытый ключ этой подписи до отправки сообщения.')
        self.peer.incoming = (n, packet, signature, self.peer.peer_hors)
        show(self.peer.received, hex_preview(packet))
        show(self.peer.received_sig, hex_preview(signature))
        show(self.peer.plain, '')
        self.peer.tabs.select(self.peer.inc)
        self.peer.note('Получен подписанный пакет. Проверьте подпись.')
        self.note('Пакет передан.')

    def inbox(self):
        if self.incoming is None:
            raise ValueError('Сначала получите пакет.')
        return self.incoming

    def check(self):
        _, packet, signature, public = self.inbox()
        valid = verify(packet, signature, public)
        self.note('Подпись действительна.' if valid else 'Подпись недействительна: пакет изменён.')

    def decrypt(self):
        n, packet, signature, public = self.inbox()
        if not verify(packet, signature, public):
            raise ValueError('Подпись недействительна. Расшифровка остановлена.')
        if not self.private or self.private[0] * self.private[1] != n:
            raise ValueError('Пакет зашифрован для другого ключа GM.')
        def ready(data):
            show(self.plain, data.decode('utf-8'))
            self.note('Подпись проверена. Сообщение расшифровано.')
        self.calculate('Расшифровка', decrypt_steps(packet, self.private), ready)

    def tamper(self):
        n, packet, signature, public = self.inbox()
        width = (n.bit_length() + 7) // 8
        c = int.from_bytes(packet[:width], 'big')
        changed = (n - c).to_bytes(width, 'big') + packet[width:]
        self.incoming = (n, changed, signature, public)
        show(self.received, hex_preview(changed))
        show(self.plain, '')
        self.note('Первый блок изменён в полученной копии. Проверьте подпись.')

    def build_numbers(self):
        line = row(self.numbers)
        ttk.Label(line, text='Длина числа в битах').pack(side='left')
        self.bits = ttk.Combobox(line, values=(256, 512, 1024, 2048), state='readonly', width=6)
        self.bits.set(1024)
        self.bits.pack(side='left', padx=6)
        self.button(line, 'Простое число', self.generate_number)
        self.button(row(self.numbers), 'Случайное число', self.random_number)
        self.number = box(self.numbers, 'Число для проверки (десятичное)', 3, editable=True)
        self.button(row(self.numbers), 'Проверить обоими тестами', self.test_number)
        line = row(self.numbers)
        self.bounds = []
        for title, default in [('От', '1000'), ('до', '1050')]:
            ttk.Label(line, text=title).pack(side='left')
            entry = ttk.Entry(line, width=10)
            entry.insert(0, default)
            entry.pack(side='left', padx=4)
            self.bounds.append(entry)
        self.button(line, 'Найти простые', self.interval)
        self.result = box(self.numbers, 'Результат', 4)

    def random_number(self):
        if self.rng is None:
            raise ValueError('Сначала подготовьте генератор на вкладке «Ключи».')
        bits = int(self.bits.get())
        n = self.rng.bits(bits) | (1 << (bits - 1))
        self.number.delete('1.0', 'end')
        self.number.insert('1.0', str(n))
        show(self.result, f'Длина числа: {bits} бит.')
        self.note('Число сгенерировано.')

    def generate_number(self):
        bits = int(self.bits.get())
        def ready(n):
            self.number.delete('1.0', 'end')
            self.number.insert('1.0', str(n))
            show(self.result, f'Вероятно простое, {bits} бит. Оба теста пройдены.')
            self.note('Число сгенерировано.')
        self.calculate('Генерация вероятно простого числа', prime_steps(bits, self.rng), ready)

    def test_number(self):
        n = decimal(self.number.get('1.0', 'end'))
        if n.bit_length() > 4096:
            raise ValueError('Введите число длиной до 4096 бит.')
        def steps():
            results = []
            for test, rounds in ((miller_rabin, 32), (solovay_strassen, 16)):
                for _ in range(rounds):
                    passed = test(n, self.rng, 1)
                    yield
                    if not passed:
                        break
                results.append(passed)
            return results
        def ready(results):
            labels = ('Миллер-Рабин (до 32 раундов)', 'Соловей-Штрассен (до 16 раундов)')
            show(self.result, '\n'.join(f'{label}: {"вероятно простое" if v else "не простое"}'
                                        for label, v in zip(labels, results)))
            self.note('Проверка завершена.')
        self.calculate('Проверка числа', steps(), ready)

    def interval(self):
        low, high = (decimal(entry.get()) for entry in self.bounds)
        if not 0 <= high - low <= 500 or max(low.bit_length(), high.bit_length()) > 2048:
            raise ValueError('Ширина интервала от 0 до 500. Каждая граница до 2048 бит.')
        def steps():
            found = []
            for n in range(max(2, low), high + 1):
                if probable_prime(n, self.rng):
                    found.append(str(n))
                yield
            return found
        def ready(found):
            show(self.result, f'Вероятно простые на [{low}, {high}]: {len(found)}\n' + ', '.join(found))
            self.note('Поиск в интервале завершён.')
        self.calculate('Поиск в интервале', steps(), ready)


def main():
    root = tk.Tk()
    other = tk.Toplevel(root)
    width = min(720, max(530, (root.winfo_screenwidth() - 48) // 2))
    height = min(720, root.winfo_screenheight() - 120)
    for window, x in ((root, 12), (other, max(24, root.winfo_screenwidth() - width - 20))):
        window.geometry(f'{width}x{height}+{x}+42')
        window.protocol('WM_DELETE_WINDOW', root.destroy)
    sender, receiver = Window(root, 'Отправитель'), Window(other, 'Получатель')
    sender.peer, receiver.peer = receiver, sender
    root.mainloop()


if __name__ == '__main__':
    main()
