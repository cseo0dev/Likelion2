public interface IWeaponObservable<T>
{
    public void Subscribe(IWeaponObserver<T> observer); // 구독
    public void Unsubscribe(IWeaponObserver<T> observer); // 구독 해제
    public void Notify(T value); // 구독자에게 알림
}
