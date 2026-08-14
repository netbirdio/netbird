#include "dialog_linux.h"

#include <gtk/gtk.h>

#include "_cgo_export.h"

static GtkApplication *app = NULL;
static GtkWidget *window = NULL;
static GtkWidget *status_label = NULL;
static char *dialog_url = NULL;

static void
on_open_clicked (GtkButton *button, gpointer user_data)
{
	gtk_widget_set_sensitive (GTK_WIDGET (button), FALSE);
	gtk_label_set_text (GTK_LABEL (status_label), "Waiting on authentication in a browser...");
	gtk_widget_set_visible (status_label, TRUE);
	goOpenClicked ((char *) dialog_url);
}

static void
on_cancel_clicked (GtkButton *button, gpointer user_data)
{
	goCancelled ();
	gtk_window_close (GTK_WINDOW (window));
}

static gboolean
on_close_request (GtkWindow *win, gpointer user_data)
{
	goCancelled ();
	return FALSE;
}

static void
activate (GtkApplication *gapp, gpointer user_data)
{
	const char **args = (const char **) user_data;
	const char *name = args[0];
	const char *url = args[1];
	GtkWidget *box;
	GtkWidget *message;
	GtkWidget *buttons;
	GtkWidget *open_button;
	GtkWidget *cancel_button;
	char *text;

	window = GTK_WIDGET (gtk_application_window_new (gapp));
	gtk_window_set_title (GTK_WINDOW (window), "NetBird VPN");
	gtk_window_set_default_size (GTK_WINDOW (window), 420, -1);

	box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);
	gtk_widget_set_margin_top (box, 18);
	gtk_widget_set_margin_bottom (box, 18);
	gtk_widget_set_margin_start (box, 18);
	gtk_widget_set_margin_end (box, 18);

	text = g_markup_printf_escaped (
		"NetBird VPN connection <b>%s</b> requires authenticating in a browser.\n\n"
		"Open the following link to continue:\n<a href=\"%s\">%s</a>",
		name, url, url);
	message = gtk_label_new (NULL);
	gtk_label_set_markup (GTK_LABEL (message), text);
	g_free (text);
	gtk_label_set_wrap (GTK_LABEL (message), TRUE);
	gtk_label_set_wrap_mode (GTK_LABEL (message), PANGO_WRAP_WORD_CHAR);
	gtk_label_set_xalign (GTK_LABEL (message), 0);
	gtk_label_set_selectable (GTK_LABEL (message), TRUE);
	gtk_box_append (GTK_BOX (box), message);

	status_label = gtk_label_new ("");
	gtk_label_set_xalign (GTK_LABEL (status_label), 0);
	gtk_widget_set_visible (status_label, FALSE);
	gtk_box_append (GTK_BOX (box), status_label);

	buttons = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	gtk_widget_set_halign (buttons, GTK_ALIGN_CENTER);
	cancel_button = gtk_button_new_with_label ("Cancel");
	open_button = gtk_button_new_with_label ("Open in Browser");
	gtk_widget_add_css_class (open_button, "suggested-action");
	gtk_box_append (GTK_BOX (buttons), cancel_button);
	gtk_box_append (GTK_BOX (buttons), open_button);
	gtk_box_append (GTK_BOX (box), buttons);

	gtk_window_set_child (GTK_WINDOW (window), box);

	g_signal_connect (open_button, "clicked", G_CALLBACK (on_open_clicked), NULL);
	g_signal_connect (cancel_button, "clicked", G_CALLBACK (on_cancel_clicked), NULL);
	g_signal_connect (window, "close-request", G_CALLBACK (on_close_request), NULL);

	gtk_window_present (GTK_WINDOW (window));
}

void
netbird_dialog_run (const char *name, const char *url)
{
	const char *args[2];

	dialog_url = g_strdup (url);
	args[0] = name;
	args[1] = url;

#if GLIB_CHECK_VERSION (2, 74, 0)
	app = gtk_application_new ("org.freedesktop.NetworkManager.netbird.AuthDialog", G_APPLICATION_DEFAULT_FLAGS);
#else
	app = gtk_application_new ("org.freedesktop.NetworkManager.netbird.AuthDialog", G_APPLICATION_FLAGS_NONE);
#endif
	g_signal_connect (app, "activate", G_CALLBACK (activate), args);
	g_application_run (G_APPLICATION (app), 0, NULL);

	g_object_unref (app);
	g_free (dialog_url);
}

static gboolean
close_window_idle (gpointer user_data)
{
	gtk_window_close (GTK_WINDOW (window));
	return G_SOURCE_REMOVE;
}

void
netbird_dialog_finish (int success)
{
	(void) success;
	g_idle_add (close_window_idle, NULL);
}
