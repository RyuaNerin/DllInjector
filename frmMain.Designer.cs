namespace DllInjector
{
    partial class frmMain
    {
        private System.ComponentModel.IContainer components = null;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            this.txtDll = new System.Windows.Forms.TextBox();
            this.btnDllSelect = new System.Windows.Forms.Button();
            this.lsvProcesses = new System.Windows.Forms.ListView();
            this.lsvProcesses0 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.lsvProcesses1 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.lsvProcesses2 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.imgIcon = new System.Windows.Forms.ImageList(this.components);
            this.btnRefresh = new System.Windows.Forms.Button();
            this.btnInject = new System.Windows.Forms.Button();
            this.ofdDll = new System.Windows.Forms.OpenFileDialog();
            this.lbl = new System.Windows.Forms.Label();
            this.windowFinder1 = new DllInjector.WindowFinder();
            this.SuspendLayout();
            // 
            // txtDll
            // 
            this.txtDll.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtDll.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.txtDll.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.FileSystem;
            this.txtDll.Location = new System.Drawing.Point(12, 12);
            this.txtDll.Name = "txtDll";
            this.txtDll.Size = new System.Drawing.Size(477, 21);
            this.txtDll.TabIndex = 0;
            // 
            // btnDllSelect
            // 
            this.btnDllSelect.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.btnDllSelect.Location = new System.Drawing.Point(495, 12);
            this.btnDllSelect.Name = "btnDllSelect";
            this.btnDllSelect.Size = new System.Drawing.Size(86, 21);
            this.btnDllSelect.TabIndex = 1;
            this.btnDllSelect.Text = "Select Dll";
            this.btnDllSelect.UseVisualStyleBackColor = true;
            this.btnDllSelect.Click += new System.EventHandler(this.btnDllSelect_Click);
            // 
            // lsvProcesses
            // 
            this.lsvProcesses.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.lsvProcesses.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.lsvProcesses0,
            this.lsvProcesses1,
            this.lsvProcesses2});
            this.lsvProcesses.FullRowSelect = true;
            this.lsvProcesses.GridLines = true;
            this.lsvProcesses.HideSelection = false;
            this.lsvProcesses.Location = new System.Drawing.Point(12, 39);
            this.lsvProcesses.MultiSelect = false;
            this.lsvProcesses.Name = "lsvProcesses";
            this.lsvProcesses.Size = new System.Drawing.Size(569, 326);
            this.lsvProcesses.SmallImageList = this.imgIcon;
            this.lsvProcesses.TabIndex = 2;
            this.lsvProcesses.UseCompatibleStateImageBehavior = false;
            this.lsvProcesses.View = System.Windows.Forms.View.Details;
            this.lsvProcesses.ColumnClick += new System.Windows.Forms.ColumnClickEventHandler(this.lsvProcesses_ColumnClick);
            // 
            // lsvProcesses0
            // 
            this.lsvProcesses0.Text = "Process Name";
            this.lsvProcesses0.Width = 120;
            // 
            // lsvProcesses1
            // 
            this.lsvProcesses1.Text = "PID";
            // 
            // lsvProcesses2
            // 
            this.lsvProcesses2.Text = "Path";
            this.lsvProcesses2.Width = 350;
            // 
            // imgIcon
            // 
            this.imgIcon.ColorDepth = System.Windows.Forms.ColorDepth.Depth24Bit;
            this.imgIcon.ImageSize = new System.Drawing.Size(22, 22);
            this.imgIcon.TransparentColor = System.Drawing.Color.FromArgb(((int)(((byte)(254)))), ((int)(((byte)(255)))), ((int)(((byte)(253)))));
            // 
            // btnRefresh
            // 
            this.btnRefresh.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.btnRefresh.Location = new System.Drawing.Point(50, 371);
            this.btnRefresh.Name = "btnRefresh";
            this.btnRefresh.Size = new System.Drawing.Size(75, 32);
            this.btnRefresh.TabIndex = 3;
            this.btnRefresh.Text = "Refresh";
            this.btnRefresh.UseVisualStyleBackColor = true;
            this.btnRefresh.Click += new System.EventHandler(this.btnRefresh_Click);
            // 
            // btnInject
            // 
            this.btnInject.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.btnInject.Location = new System.Drawing.Point(473, 371);
            this.btnInject.Name = "btnInject";
            this.btnInject.Size = new System.Drawing.Size(108, 32);
            this.btnInject.TabIndex = 4;
            this.btnInject.Text = "Inject Dll";
            this.btnInject.UseVisualStyleBackColor = true;
            this.btnInject.Click += new System.EventHandler(this.btnInject_Click);
            // 
            // ofdDll
            // 
            this.ofdDll.Filter = "DLL File (*.dll)|*.dll";
            // 
            // lbl
            // 
            this.lbl.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.lbl.AutoSize = true;
            this.lbl.Cursor = System.Windows.Forms.Cursors.Hand;
            this.lbl.Location = new System.Drawing.Point(273, 391);
            this.lbl.Name = "lbl";
            this.lbl.Size = new System.Drawing.Size(194, 12);
            this.lbl.TabIndex = 6;
            this.lbl.Text = "copyright (C) 2016, By RyuaNerin";
            this.lbl.DoubleClick += new System.EventHandler(this.lbl_DoubleClick);
            // 
            // windowFinder1
            // 
            this.windowFinder1.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.windowFinder1.Location = new System.Drawing.Point(12, 371);
            this.windowFinder1.Name = "windowFinder1";
            this.windowFinder1.Size = new System.Drawing.Size(32, 32);
            this.windowFinder1.TabIndex = 5;
            this.windowFinder1.Text = "windowFinder1";
            this.windowFinder1.SelectedWindow += new System.EventHandler<DllInjector.WindowFinderArgs>(this.windowFinder1_SelectedWindow);
            // 
            // frmMain
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(593, 415);
            this.Controls.Add(this.lbl);
            this.Controls.Add(this.windowFinder1);
            this.Controls.Add(this.btnInject);
            this.Controls.Add(this.btnRefresh);
            this.Controls.Add(this.lsvProcesses);
            this.Controls.Add(this.btnDllSelect);
            this.Controls.Add(this.txtDll);
            this.DoubleBuffered = true;
            this.Name = "frmMain";
            this.Text = "DllInjector";
            this.Load += new System.EventHandler(this.frmMain_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        private System.Windows.Forms.TextBox txtDll;
        private System.Windows.Forms.Button btnDllSelect;
        private System.Windows.Forms.ListView lsvProcesses;
        private System.Windows.Forms.Button btnRefresh;
        private System.Windows.Forms.ColumnHeader lsvProcesses0;
        private System.Windows.Forms.ColumnHeader lsvProcesses1;
        private System.Windows.Forms.ColumnHeader lsvProcesses2;
        private System.Windows.Forms.Button btnInject;
        private System.Windows.Forms.ImageList imgIcon;
        private System.Windows.Forms.OpenFileDialog ofdDll;
        private WindowFinder windowFinder1;
        private System.Windows.Forms.Label lbl;
    }
}

