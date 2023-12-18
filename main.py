import argparse
from linker import linker

if __name__ == '__main__':
    parser = argparse.ArgumentParser('static_linker', description='Static Linker for x86-64 Linux')
    parser.add_argument('objs', type=str, nargs='+', help='Relocatable object files (input)')
    parser.add_argument('-l', '--arcs', type=str, nargs='+', help='Static libraries to be linked (input)')
    parser.add_argument('-e', '--executable', type=str, help='Executable file (output)')
    parser.add_argument('-a', '--archive', type=str, help='Archive files (output)')
    parser.add_argument('-so', '--shared_library', type=str, help='Shared library (output)')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Verbose mode')
    args = parser.parse_args()

    if not args.objs:
        raise ValueError('No input relocatable object files')
    if not args.executable and not args.archive and not args.shared_library:
        raise ValueError('No output file designated')

    if args.executable:
        if not args.executable.endswith('.out'):
            args.executable += '.out'
        if args.arcs:
            print('{} --> {}'.format(args.objs + args.arcs, args.executable))
            linker.link_objs_arcs_to_exe(args.objs, args.arcs, args.executable)
        else:
            print('{} --> {}'.format(args.objs, args.executable))
            linker.link_objs_to_exe(args.objs, args.executable)

    if args.archive:
        if not args.archive.endswith('.a'):
            args.archive += '.a'
        print('{} --> {}'.format(args.objs, args.archive))
        linker.link_objs_to_arc(args.objs, args.archive)
        
    if args.shared_library:
        if not args.shared_library.endswith('.so'):
            args.shared_library += '.so'
        print('{} --> {}'.format(args.objs, args.shared_library))
        linker.link_objs_to_so(args.objs, args.shared_library)
        
