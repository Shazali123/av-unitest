"""
AV Benchmark Testing Framework - Main Application
Phase 1: Core benchmark with modular testing
"""

import customtkinter as ctk
import threading
import av_detector
from module_manager import ModuleManager
from results_handler import ResultsHandler


class BenchmarkApp(ctk.CTk):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        
        # Configure window
        self.title("AV Benchmark Testing Framework")
        self.geometry("900x700")
        self.resizable(False, False)
        
        # Set theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Initialize components
        self.module_manager = ModuleManager()
        self.results_handler = ResultsHandler()
        self.av_name = "Detecting..."
        self.module_results = []
        
        # UI state
        self.current_screen = "start"
        
        # Create main container
        self.main_container = ctk.CTkFrame(self)
        self.main_container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Show start screen
        self.show_start_screen()
        
        # Detect AV in background
        threading.Thread(target=self.detect_av, daemon=True).start()
        
    def detect_av(self):
        """Detect antivirus in background"""
        self.av_name = av_detector.detect_antivirus()
        if hasattr(self, 'av_label'):
            self.av_label.configure(text=f"🛡️ Detected AV: {self.av_name}")
            
    def clear_screen(self):
        """Clear current screen"""
        for widget in self.main_container.winfo_children():
            widget.destroy()
            
    def show_start_screen(self):
        """Display start screen"""
        self.clear_screen()
        self.current_screen = "start"
        
        # Title
        title = ctk.CTkLabel(
            self.main_container,
            text="AV Benchmark Testing Framework",
            font=ctk.CTkFont(size=32, weight="bold")
        )
        title.pack(pady=(40, 10))
        
        # Subtitle
        subtitle = ctk.CTkLabel(
            self.main_container,
            text="Phase 1 - Module Testing",
            font=ctk.CTkFont(size=18)
        )
        subtitle.pack(pady=(0, 30))
        
        # Info card
        info_frame = ctk.CTkFrame(self.main_container)
        info_frame.pack(pady=20, padx=40, fill="x")
        
        # AV detection
        self.av_label = ctk.CTkLabel(
            info_frame,
            text=f"🛡️ Detected AV: {self.av_name}",
            font=ctk.CTkFont(size=16)
        )
        self.av_label.pack(pady=15)
        
        # Discover modules
        self.module_manager.discover_modules()
        module_count = self.module_manager.get_module_count()
        
        modules_label = ctk.CTkLabel(
            info_frame,
            text=f"📦 Modules Found: {module_count}",
            font=ctk.CTkFont(size=16)
        )
        modules_label.pack(pady=15)
        
        # Module list
        if module_count > 0:
            modules_list_frame = ctk.CTkFrame(self.main_container)
            modules_list_frame.pack(pady=20, padx=60, fill="both", expand=True)
            
            list_title = ctk.CTkLabel(
                modules_list_frame,
                text="Test Modules:",
                font=ctk.CTkFont(size=16, weight="bold")
            )
            list_title.pack(pady=(15, 10))
            
            for module_info in self.module_manager.get_module_list():
                module_label = ctk.CTkLabel(
                    modules_list_frame,
                    text=f"  {module_info['id']}. {module_info['name']} - {module_info['description']}",
                    font=ctk.CTkFont(size=14),
                    anchor="w"
                )
                module_label.pack(pady=5, padx=20, anchor="w")
                
        # Start button
        start_btn = ctk.CTkButton(
            self.main_container,
            text="Start Benchmark",
            font=ctk.CTkFont(size=20, weight="bold"),
            height=60,
            corner_radius=10,
            command=self.start_benchmark
        )
        start_btn.pack(pady=30)
        
    def start_benchmark(self):
        """Start benchmark testing"""
        self.show_loading_screen()
        # Run modules in background thread
        threading.Thread(target=self.run_modules, daemon=True).start()
        
    def show_loading_screen(self):
        """Display loading screen"""
        self.clear_screen()
        self.current_screen = "loading"
        
        # Title
        title = ctk.CTkLabel(
            self.main_container,
            text="Running Benchmark...",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title.pack(pady=(60, 30))
        
        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(
            self.main_container,
            width=600,
            height=30
        )
        self.progress_bar.pack(pady=20)
        self.progress_bar.set(0)
        
        # Status label
        self.status_label = ctk.CTkLabel(
            self.main_container,
            text="Initializing...",
            font=ctk.CTkFont(size=16)
        )
        self.status_label.pack(pady=20)
        
        # Console output
        console_frame = ctk.CTkFrame(self.main_container)
        console_frame.pack(pady=20, padx=40, fill="both", expand=True)
        
        self.console_text = ctk.CTkTextbox(
            console_frame,
            font=ctk.CTkFont(family="Consolas", size=12),
            width=800,
            height=300
        )
        self.console_text.pack(pady=10, padx=10, fill="both", expand=True)
        
    def update_progress(self, current, total, module_name):
        """Update progress bar and status"""
        progress = current / total
        self.progress_bar.set(progress)
        self.status_label.configure(text=f"Running Module {current}/{total}: {module_name}")
        self.console_text.insert("end", f"\n[{current}/{total}] Starting: {module_name}...")
        self.console_text.see("end")
        
    def run_modules(self):
        """Run all modules (background thread)"""
        # Run modules with progress callback
        self.module_results = self.module_manager.run_modules(
            progress_callback=self.update_progress
        )
        
        # Show results screen
        self.after(500, self.show_results_screen)
        
    def show_results_screen(self):
        """Display results screen"""
        self.clear_screen()
        self.current_screen = "results"
        
        # Title
        title = ctk.CTkLabel(
            self.main_container,
            text="✓ Benchmark Complete!",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color="green"
        )
        title.pack(pady=(30, 20))
        
        # Results container
        results_frame = ctk.CTkScrollableFrame(
            self.main_container,
            width=800,
            height=350
        )
        results_frame.pack(pady=20, padx=20, fill="both", expand=True)
        
        # Compile results text
        results_text = self.results_handler.compile_results(self.module_results, self.av_name)
        
        # Display results
        results_display = ctk.CTkTextbox(
            results_frame,
            font=ctk.CTkFont(family="Consolas", size=11),
            width=760,
            height=320
        )
        results_display.pack(pady=10, padx=10)
        results_display.insert("1.0", results_text)
        results_display.configure(state="disabled")
        
        # Store results text for export
        self.current_results_text = results_text
        
        # Button frame
        button_frame = ctk.CTkFrame(self.main_container)
        button_frame.pack(pady=20)
        
        # Export button
        export_btn = ctk.CTkButton(
            button_frame,
            text="📄 Export to TXT",
            font=ctk.CTkFont(size=16, weight="bold"),
            height=45,
            width=200,
            command=self.export_results
        )
        export_btn.pack(side="left", padx=10)
        
        # Upload button (placeholder)
        upload_btn = ctk.CTkButton(
            button_frame,
            text="📤 Upload to Server",
            font=ctk.CTkFont(size=16, weight="bold"),
            height=45,
            width=200,
            state="disabled",
            command=self.upload_results
        )
        upload_btn.pack(side="left", padx=10)
        
        # Run again button
        again_btn = ctk.CTkButton(
            button_frame,
            text="🔄 Run Again",
            font=ctk.CTkFont(size=16, weight="bold"),
            height=45,
            width=200,
            fg_color="gray",
            command=self.show_start_screen
        )
        again_btn.pack(side="left", padx=10)
        
    def export_results(self):
        """Export results to TXT file"""
        try:
            filepath = self.results_handler.export_to_txt(self.current_results_text)
            
            # Show success message
            success_window = ctk.CTkToplevel(self)
            success_window.title("Export Successful")
            success_window.geometry("400x150")
            success_window.resizable(False, False)
            
            msg = ctk.CTkLabel(
                success_window,
                text=f"✓ Results exported successfully!\n\n{filepath}",
                font=ctk.CTkFont(size=14)
            )
            msg.pack(pady=30)
            
            close_btn = ctk.CTkButton(
                success_window,
                text="OK",
                command=success_window.destroy
            )
            close_btn.pack(pady=10)
            
        except Exception as e:
            print(f"Export error: {e}")
            
    def upload_results(self):
        """Placeholder for upload to server"""
        # This will be implemented in Phase 3/4
        pass


def main():
    """Main entry point"""
    app = BenchmarkApp()
    app.mainloop()


if __name__ == "__main__":
    main()
