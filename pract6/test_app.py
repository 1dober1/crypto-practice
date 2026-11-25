import sys
import unittest
from unittest.mock import Mock

from app import Window
from crypto import Generator


def headless(name):
    # Подставляем виджеты, сохраняя обработчики кнопок и вычисления приложения.
    side = Window.__new__(Window)
    side.name = name
    for field in ('window progress status log source key_status key_info private_info cipher signature received '
                  'received_sig plain tabs inc number bits result').split():
        setattr(side, field, Mock())
    side.bounds = [Mock(), Mock()]
    side.rng = Generator(name.encode())
    side.outgoing = side.incoming = side.private = side.hors = side.peer_n = side.peer_hors = None
    side.busy = False
    callbacks = []
    side.window.after.side_effect = lambda delay, callback: callbacks.append(callback)

    def drain():
        while callbacks:
            callbacks.pop(0)()
    return side, drain


class WindowTests(unittest.TestCase):
    def test_exchange(self):
        a, finish_a = headless('Отправитель')
        b, finish_b = headless('Получатель')
        a.peer, b.peer = b, a
        a.source.get.return_value = 'Привет!'
        with self.assertRaises(ValueError):
            a.encrypt()
        a.new_hors()
        finish_a()
        b.new_gm()
        finish_b()
        a.exchange()
        b.exchange()
        a.encrypt()
        finish_a()
        a.sign()
        with self.assertRaises(ValueError):
            a.sign()
        a.source.get.return_value = 'Другой текст'
        with self.assertRaises(ValueError):
            a.send()
        a.source.get.return_value = 'Привет!'
        a.send()
        b.check()
        b.status.set.assert_called_with('Подпись действительна.')
        b.decrypt()
        finish_b()
        b.plain.insert.assert_called_with('1.0', 'Привет!')
        b.tamper()
        b.check()
        b.status.set.assert_called_with('Подпись недействительна: пакет изменён.')
        with self.assertRaises(ValueError):
            b.decrypt()
        a.send()
        b.check()
        b.status.set.assert_called_with('Подпись действительна.')
        a.new_hors()
        finish_a()
        a.exchange()
        b.check()
        b.status.set.assert_called_with('Подпись действительна.')
        a.sign()
        a.send()
        b.decrypt()
        finish_b()
        b.plain.insert.assert_called_with('1.0', 'Привет!')

    def test_prime_panel(self):
        side, drain = headless('Числа')
        side.bits.get.return_value = '256'
        side.generate_number()
        drain()
        number = side.number.insert.call_args.args[1]
        self.assertEqual(int(number).bit_length(), 256)
        side.number.get.return_value = number
        side.test_number()
        drain()
        self.assertEqual(side.result.insert.call_args.args[1].count('вероятно простое'), 2)
        side.bounds[0].get.return_value, side.bounds[1].get.return_value = '11', '19'
        side.interval()
        drain()
        self.assertTrue(side.result.insert.call_args.args[1].endswith('11, 13, 17, 19'))

    def test_error_during_calculation(self):
        side, drain = headless('Ошибки')
        def fails():
            yield
            raise ValueError('Ошибка данных')
        side.calculate('Проверка', fails(), self.fail)
        drain()
        self.assertFalse(side.busy)
        side.status.set.assert_called_with('Ошибка данных')


def desktop_test():
    import tkinter as tk
    root = tk.Tk()
    try:
        sender = Window(root, 'Отправитель')
        receiver = Window(tk.Toplevel(root), 'Получатель')
        sender.peer, receiver.peer = receiver, sender
        root.update()
        assert sender.window.title() == 'Отправитель'
        assert receiver.window.title() == 'Получатель'
        for side in (sender, receiver):
            area = next(widget for widget in side.keys.winfo_children()
                        if isinstance(widget, tk.Canvas))
            for i in range(96):
                area.event_generate('<Motion>', x=i + 1, y=i % 40)
            assert side.rng is not None
            assert area.winfo_ismapped()
            assert side.log.winfo_ismapped()
            assert side.key_info.winfo_ismapped()

        def wait(side):
            while side.busy:
                root.update()
        receiver.new_gm()
        wait(receiver)
        sender.new_hors()
        wait(sender)
        receiver.exchange()
        sender.exchange()
        sender.source.insert('1.0', 'Привет')
        sender.encrypt()
        wait(sender)
        sender.sign()
        sender.send()
        receiver.check()
        assert receiver.status.get() == 'Подпись действительна.'
        receiver.decrypt()
        wait(receiver)
        assert receiver.plain.get('1.0', 'end-1c') == 'Привет'
        assert receiver.received.winfo_ismapped()
        assert receiver.received_sig.winfo_ismapped()
        receiver.tamper()
        receiver.check()
        assert 'недействительна' in receiver.status.get()
        print('OK: два окна, обмен ключами, сообщение, подпись и подмена.')
    finally:
        root.destroy()


if __name__ == '__main__':
    if sys.argv[1:] == ['--gui']:
        desktop_test()
    else:
        unittest.main()
