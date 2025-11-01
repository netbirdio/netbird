import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { User, CheckCircle2, RefreshCw, Trash2, Plus, X } from 'lucide-react';
import { useStore } from '../store/useStore';

export default function ProfilesPage() {
  const { profiles, activeProfile, refreshProfiles, switchProfile, addProfile, removeProfile } = useStore();
  const [deletingProfile, setDeletingProfile] = useState<string | null>(null);
  const [isAddingProfile, setIsAddingProfile] = useState(false);
  const [showAddForm, setShowAddForm] = useState(false);
  const [newProfileName, setNewProfileName] = useState('');

  useEffect(() => {
    refreshProfiles();
  }, [refreshProfiles]);

  const handleSwitchProfile = async (profileId: string) => {
    console.log('Switching to profile:', profileId);
    try {
      await switchProfile(profileId);
      console.log('Switch profile call completed');
      // Refresh profiles to get updated active state
      await refreshProfiles();
      console.log('Profiles refreshed after switch');
    } catch (error) {
      console.error('Switch profile error:', error);
    }
  };

  const handleAddProfileClick = () => {
    setShowAddForm(true);
    setNewProfileName('');
  };

  const handleAddProfileSubmit = async () => {
    if (!newProfileName || newProfileName.trim() === '') {
      return;
    }

    try {
      setIsAddingProfile(true);
      await addProfile(newProfileName.trim());
      await refreshProfiles();
      setShowAddForm(false);
      setNewProfileName('');
    } catch (error) {
      console.error('Add profile error:', error);
      alert('Failed to add profile');
    } finally {
      setIsAddingProfile(false);
    }
  };

  const handleAddProfileCancel = () => {
    setShowAddForm(false);
    setNewProfileName('');
  };

  const handleDeleteProfile = async (profileId: string, event: React.MouseEvent) => {
    event.stopPropagation(); // Prevent profile switching when clicking delete

    if (!confirm(`Are you sure you want to delete the profile "${profileId}"?`)) {
      return;
    }

    try {
      setDeletingProfile(profileId);
      await removeProfile(profileId);
      await refreshProfiles();
    } catch (error) {
      console.error('Delete profile error:', error);
      alert('Failed to delete profile');
    } finally {
      setDeletingProfile(null);
    }
  };

  // Use profiles as-is without sorting
  const sortedProfiles = profiles;

  return (
    <div className="h-full overflow-auto p-8">
      <div className="max-w-4xl mx-auto space-y-6">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <h1 className="text-3xl font-bold text-text-light mb-2">Profiles</h1>
          <p className="text-text-muted">Manage your NetBird profiles</p>
        </motion.div>

        {/* All Profiles */}
        <div className="space-y-3">
          <h2 className="text-xl font-bold text-text-light">All Profiles</h2>
          {sortedProfiles.length === 0 ? (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="glass rounded-glass p-12 text-center shadow-glass"
            >
              <User className="w-16 h-16 text-text-muted mx-auto mb-4" />
              <h3 className="text-xl font-bold text-text-light mb-2">No Profiles</h3>
              <p className="text-text-muted">Add a profile to get started</p>
            </motion.div>
          ) : (
            sortedProfiles.map((profile, index) => {
              // Use the active flag from the profile (set by daemon)
              const isActive = profile.active;
              return (
                <motion.div
                  key={profile.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.05 }}
                  className={`glass glass-hover rounded-glass p-6  cursor-pointer transition-all ${
                    isActive ? 'border-2 border-icy-blue/20' : ''
                  }`}
                  onClick={() => {
                    console.log('Clicked profile:', profile.id, 'isActive:', isActive);
                    if (!isActive) {
                      handleSwitchProfile(profile.id);
                    }
                  }}
                >
                  <div className="flex items-center gap-4">
                    <div
                      className={`w-12 h-12 rounded-full flex items-center justify-center ${
                        isActive ? 'bg-icy-blue/20' : 'bg-text-muted/20'
                      }`}
                    >
                      <User
                        className={`w-6 h-6 ${
                          isActive ? 'text-icy-blue' : 'text-text-muted'
                        }`}
                      />
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <h3 className="text-lg font-bold text-text-light">{profile.name}</h3>
                        {isActive && (
                          <span className="px-2 py-1 bg-icy-blue/20 text-icy-blue rounded-full text-xs font-medium">
                            Active
                          </span>
                        )}
                      </div>
                      {profile.email && (
                        <p className="text-sm text-text-muted mt-1">{profile.email}</p>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      {isActive && <CheckCircle2 className="w-5 h-5 text-icy-blue" />}
                      {!isActive && (
                        <button
                          onClick={(e) => handleDeleteProfile(profile.id, e)}
                          disabled={deletingProfile === profile.id}
                          className="p-2 rounded-lg hover:bg-red-500/20 text-text-muted hover:text-red-400 transition-all disabled:opacity-50"
                          title="Delete profile"
                        >
                          <Trash2 className="w-5 h-5" />
                        </button>
                      )}
                    </div>
                  </div>
                </motion.div>
              );
            })
          )}

          {/* Add Profile Button / Form */}
          {!showAddForm ? (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: sortedProfiles.length * 0.05 }}
              className="glass glass-hover rounded-glass p-6  cursor-pointer transition-all border-2 border-dashed border-text-muted/20 hover:border-icy-blue/40"
              onClick={handleAddProfileClick}
            >
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-full flex items-center justify-center bg-text-muted/10">
                  <Plus className="w-6 h-6 text-text-muted" />
                </div>
                <div className="flex-1">
                  <h3 className="text-lg font-bold text-text-muted">Add Profile</h3>
                  <p className="text-sm text-text-muted/70 mt-1">Create a new profile</p>
                </div>
              </div>
            </motion.div>
          ) : (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="glass rounded-glass p-6  border-2 border-icy-blue/40 shadow-glass"
            >
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-full flex items-center justify-center bg-icy-blue/20">
                  <Plus className="w-6 h-6 text-icy-blue" />
                </div>
                <div className="flex-1">
                  <input
                    type="text"
                    value={newProfileName}
                    onChange={(e) => setNewProfileName(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') handleAddProfileSubmit();
                      if (e.key === 'Escape') handleAddProfileCancel();
                    }}
                    placeholder="Enter profile name..."
                    className="w-full px-3 py-2 bg-background-dark border border-text-muted/20 rounded-lg text-text-light placeholder-text-muted/50 focus:outline-none focus:border-icy-blue/50"
                    autoFocus
                  />
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={handleAddProfileCancel}
                    className="p-2 rounded-lg hover:bg-text-muted/10 text-text-muted hover:text-text-light transition-all"
                    title="Cancel"
                  >
                    <X className="w-5 h-5" />
                  </button>
                  <button
                    onClick={handleAddProfileSubmit}
                    disabled={isAddingProfile || !newProfileName.trim()}
                    className="px-4 py-2 rounded-lg bg-icy-blue text-text-light hover:bg-icy-blue/80 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {isAddingProfile ? 'Adding...' : 'Add'}
                  </button>
                </div>
              </div>
            </motion.div>
          )}
        </div>
      </div>
    </div>
  );
}
