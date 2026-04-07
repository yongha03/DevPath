export const PROFILE_UPDATED_EVENT = 'devpath:profile-updated'

export type ProfileSyncPayload = {
  name: string
  profileImage: string | null
}

export function notifyProfileUpdated(payload: ProfileSyncPayload) {
  window.dispatchEvent(new CustomEvent<ProfileSyncPayload>(PROFILE_UPDATED_EVENT, { detail: payload }))
}
