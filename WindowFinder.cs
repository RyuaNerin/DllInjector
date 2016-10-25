using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace DllInjector
{
    [DesignerCategory("code")]
    public class WindowFinderArgs : EventArgs
    {
        public WindowFinderArgs(IntPtr handle)
        {
            this.m_handle = handle;
        }

        private readonly IntPtr m_handle;
        public IntPtr Handle { get { return this.m_handle; } }
    }

    [DesignerCategory("CODE")]
    public partial class WindowFinder : Control
    {
        private static readonly byte[] RawCursor =
        {
            0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x20, 0x20,  0x00, 0x00, 0x0F, 0x00, 0x0F, 0x00, 0x30, 0x01,
            0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x28, 0x00,  0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x40, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFC,
            0x3F, 0xFF, 0xFF, 0xE2, 0xC7, 0xFF, 0xFF, 0xDE,  0xFB, 0xFF, 0xFF, 0xBE, 0xFD, 0xFF, 0xFF, 0x7E,
            0xFE, 0xFF, 0xFE, 0xFE, 0x7F, 0x7F, 0xFE, 0xF8,  0x9F, 0x7F, 0xFE, 0xF6, 0xEF, 0x7F, 0xFD, 0xF6,
            0xEF, 0xBF, 0xFD, 0xEE, 0xF7, 0xBF, 0xF8, 0x00,  0x00, 0x1F, 0xFD, 0xF6, 0xEF, 0xBF, 0xFE, 0xF6,
            0xEF, 0x7F, 0xFE, 0xF8, 0x9F, 0x7F, 0xFE, 0xFE,  0x7F, 0x7F, 0xFF, 0x7E, 0xFE, 0xFF, 0xFF, 0xBE,
            0xFD, 0xFF, 0xFF, 0xDE, 0xFB, 0xFF, 0xFF, 0xE2,  0xC7, 0xFF, 0xFF, 0xFC, 0x3F, 0xFF, 0xFF, 0xFE,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
        };

        private static readonly Cursor CursorIcon;
        private static readonly Size CursorSize;

        static WindowFinder()
        {
            using (var mem = new MemoryStream(WindowFinder.RawCursor))
            {
                mem.Position = 0;
                WindowFinder.CursorIcon = new Cursor(mem);
            }

            WindowFinder.CursorSize = WindowFinder.CursorIcon.Size;
        }

        public WindowFinder()
        {
        }

        public event EventHandler<WindowFinderArgs> SelectedWindow;

        private bool m_capturing;
        private IntPtr m_lastCursor;
        
        protected override void SetBoundsCore(int x, int y, int width, int height, BoundsSpecified specified)
        {
            base.SetBoundsCore(x, y, WindowFinder.CursorSize.Width, WindowFinder.CursorSize.Height, specified);
        }

        protected override void OnPaintBackground(PaintEventArgs pevent)
        {
            base.OnPaintBackground(pevent);

            if (!this.m_capturing)
                WindowFinder.CursorIcon.Draw(pevent.Graphics, pevent.ClipRectangle);
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);

            this.m_capturing = true;
            this.Invalidate();

            NativeMethods.POINT position;
            if (NativeMethods.GetCursorPos(out position))
                NativeMethods.SetCursorPos(position.X + this.Width / 2 - e.X, position.Y + this.Height / 2 - e.Y);

            this.m_lastCursor = NativeMethods.SetCursor(WindowFinder.CursorIcon.Handle);

            NativeMethods.SetCapture(this.Handle);

            var parent = this.Parent.Parent;
            if (parent != null)
            {
                while (parent != null)
                {
                    if (parent.Parent == null)
                        break;

                    parent = parent.Parent;
                }
                    
                NativeMethods.ShowWindow(this.Parent.Parent.Handle, NativeMethods.SW_HIDE);
            }
        }

        protected override void OnMouseUp(MouseEventArgs e)
        {
            base.OnMouseUp(e);

            if (this.m_capturing)
            {
                this.m_capturing = false;
                this.Invalidate();

                NativeMethods.ReleaseCapture();

                NativeMethods.SetCursor(this.m_lastCursor);
                
                NativeMethods.ShowWindow(this.Parent.Handle, NativeMethods.SW_SHOWNORMAL);

                NativeMethods.POINT position;
                if (NativeMethods.GetCursorPos(out position))
                {
                    var hwnd = NativeMethods.WindowFromPoint(position);
                    if (!NativeMethods.IsWindow(hwnd))
                        return;

                    var lst = new List<IntPtr>();

                    Control ctrl = this;
                    do 
                    {
                        lst.Add(ctrl.Handle);
                        ctrl = ctrl.Parent;
                    } while (ctrl != null);
                    
                    var parentHwnd = hwnd;
                    do
                    {
                        if (lst.Contains(parentHwnd))
                            return;
                    } while ((parentHwnd = NativeMethods.GetParent(parentHwnd)) != IntPtr.Zero);


                    if (this.SelectedWindow != null)
                        this.SelectedWindow(this, new WindowFinderArgs(hwnd));
                }
            }
        }

        private static class NativeMethods
        {
            [DllImport("user32.dll")]
            public static extern bool SetCursorPos(int X, int Y);

            [DllImport("user32.dll")]
            public static extern IntPtr SetCursor(IntPtr hCursor);

            [DllImport("user32.dll")]
            public static extern IntPtr SetCapture(IntPtr hWnd);

            [DllImport("user32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool ShowWindow(IntPtr hWnd, uint nCmdShow);

            [DllImport("user32.dll")]
            public static extern bool ReleaseCapture();

            [DllImport("user32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool GetCursorPos(out POINT lpPoint);

            [DllImport("user32.dll")]
            public static extern IntPtr WindowFromPoint(POINT p);

            [DllImport("user32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool IsWindow(IntPtr hWnd);

            [DllImport("user32.dll")]
            public static extern IntPtr GetParent(IntPtr hWnd);

            public const uint SW_HIDE = 0x00;
            public const uint SW_SHOWNORMAL = 0x01;

            [StructLayout(LayoutKind.Sequential)]
            public struct POINT
            {
                private static readonly int HalfBits = (IntPtr.Size / 2) * 8;

                public POINT(int x, int y)
                {
                    this.Raw = new IntPtr((y << HalfBits) | x);
                }

                public POINT(System.Drawing.Point pt) : this(pt.X, pt.Y)
                {
                }

                public IntPtr Raw;
                
                public int X
                {
                    get { return (int)(Raw.ToInt64() & ((1L << HalfBits) - 1)); }
                    set { this.Raw = new IntPtr((this.X << HalfBits) | value); }
                }
                public int Y
                {
                    get { return (int)(Raw.ToInt64() >> HalfBits); }
                    set { this.Raw = new IntPtr((value << HalfBits) | this.Y); }
                }

                public static implicit operator System.Drawing.Point(POINT p)
                {
                    return new System.Drawing.Point(p.X, p.Y);
                }

                public static implicit operator POINT(System.Drawing.Point p)
                {
                    return new POINT(p.X, p.Y);
                }
            }
        }
    }
}
